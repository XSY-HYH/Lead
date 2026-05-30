using System.Reflection;
using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;

namespace Lead.Security;

public sealed class TamperGuard : IDisposable
{
    private const uint PAGE_EXECUTE_READ = 0x20;
    private const int STATUS_ACCESS_VIOLATION = unchecked((int)0xC0000005);
    private const long EXCEPTION_CONTINUE_SEARCH = 0;

    [DllImport("kernel32.dll")]
    private static extern bool VirtualProtect(IntPtr lpAddress, UIntPtr dwSize, uint flNewProtect, out uint lpflOldProtect);

    [DllImport("kernel32.dll")]
    private static extern IntPtr AddVectoredExceptionHandler(uint first, IntPtr handler);

    [DllImport("kernel32.dll")]
    private static extern int RemoveVectoredExceptionHandler(IntPtr handle);

    [DllImport("libc")]
    private static extern int mprotect(IntPtr addr, UIntPtr len, int prot);

    private const int PROT_READ = 0x1;
    private const int PROT_EXEC = 0x4;

    [UnmanagedFunctionPointer(CallingConvention.StdCall)]
    private delegate long VectoredHandlerDelegate(IntPtr exceptionPointers);

    private static IntPtr s_regionsBuffer;
    private static int s_regionCount;
    private static VectoredHandlerDelegate? s_handler;
    private static IntPtr s_vehHandle;
    private static bool s_active;

    private readonly List<(IntPtr Start, IntPtr End, string Name)> _pendingRegions = new();
    private bool _disposed;

    public TamperGuard Protect(MethodInfo method)
    {
        ObjectDisposedException.ThrowIf(_disposed, this);

        RuntimeHelpers.PrepareMethod(method.MethodHandle);
        var entry = ResolveEntryPoint(method.MethodHandle.GetFunctionPointer());

        var pageSize = Environment.SystemPageSize;
        var pageStart = (long)entry & ~(pageSize - 1);
        var pageEnd = pageStart + pageSize;

        _pendingRegions.Add(((IntPtr)pageStart, (IntPtr)pageEnd, $"{method.DeclaringType?.Name}::{method.Name}"));
        return this;
    }

    public void Activate()
    {
        ObjectDisposedException.ThrowIf(_disposed, this);
        if (s_active) return;

        s_regionCount = _pendingRegions.Count;
        if (s_regionCount == 0) return;

        s_regionsBuffer = Marshal.AllocHGlobal(s_regionCount * 16);

        for (int i = 0; i < s_regionCount; i++)
        {
            var (start, end, _) = _pendingRegions[i];
            Marshal.WriteIntPtr(s_regionsBuffer, i * 16, start);
            Marshal.WriteIntPtr(s_regionsBuffer, i * 16 + 8, end);
        }

        if (RuntimeInformation.IsOSPlatform(OSPlatform.Windows))
        {
            foreach (var (start, end, _) in _pendingRegions)
                VirtualProtect(start, (UIntPtr)(end.ToInt64() - start.ToInt64()), PAGE_EXECUTE_READ, out _);

            s_handler = StaticOnVectoredException;
            s_vehHandle = AddVectoredExceptionHandler(1, Marshal.GetFunctionPointerForDelegate(s_handler));
        }
        else if (RuntimeInformation.IsOSPlatform(OSPlatform.Linux) ||
                 RuntimeInformation.IsOSPlatform(OSPlatform.OSX) ||
                 RuntimeInformation.IsOSPlatform(OSPlatform.FreeBSD))
        {
            foreach (var (start, end, _) in _pendingRegions)
                mprotect(start, (UIntPtr)(end.ToInt64() - start.ToInt64()), PROT_READ | PROT_EXEC);
        }

        s_active = true;
    }

    private static long StaticOnVectoredException(IntPtr exceptionPointers)
    {
        if (exceptionPointers == IntPtr.Zero || s_regionsBuffer == IntPtr.Zero || s_regionCount == 0)
            return EXCEPTION_CONTINUE_SEARCH;

        var exceptionRecord = Marshal.ReadIntPtr(exceptionPointers);
        if (exceptionRecord == IntPtr.Zero)
            return EXCEPTION_CONTINUE_SEARCH;

        var exceptionCode = Marshal.ReadInt32(exceptionRecord);
        if (exceptionCode != STATUS_ACCESS_VIOLATION)
            return EXCEPTION_CONTINUE_SEARCH;

        var ptrSize = IntPtr.Size;
        var numParamsOffset = 8 + ptrSize * 2;
        var numParams = Marshal.ReadInt32(exceptionRecord, numParamsOffset);
        if (numParams < 2)
            return EXCEPTION_CONTINUE_SEARCH;

        var infoOffset = (numParamsOffset + 4 + ptrSize - 1) & ~(ptrSize - 1);
        var writeFlagLong = Marshal.ReadIntPtr(exceptionRecord, infoOffset).ToInt64();
        if (writeFlagLong != 1)
            return EXCEPTION_CONTINUE_SEARCH;

        var faultAddress = Marshal.ReadIntPtr(exceptionRecord, infoOffset + ptrSize);

        for (int i = 0; i < s_regionCount; i++)
        {
            var start = Marshal.ReadIntPtr(s_regionsBuffer, i * 16);
            var end = Marshal.ReadIntPtr(s_regionsBuffer, i * 16 + 8);
            if (faultAddress.ToInt64() >= start.ToInt64() && faultAddress.ToInt64() < end.ToInt64())
            {
                Environment.FailFast("LEAD TAMPER: write to protected method memory detected");
            }
        }

        return EXCEPTION_CONTINUE_SEARCH;
    }

    private static IntPtr ResolveEntryPoint(IntPtr funcPtr)
    {
        try
        {
            var bytes = new byte[16];
            Marshal.Copy(funcPtr, bytes, 0, 16);

            if (bytes[0] == 0xFF && bytes[1] == 0x25)
            {
                var offset = BitConverter.ToInt32(bytes, 2);
                var target = Marshal.ReadIntPtr(funcPtr + 6 + offset);
                if (target != IntPtr.Zero)
                    return target;
            }

            if (bytes[0] == 0xE9)
            {
                var offset = BitConverter.ToInt32(bytes, 1);
                return funcPtr + 5 + offset;
            }
        }
        catch { }
        return funcPtr;
    }

    public void Dispose()
    {
        if (_disposed) return;
        _disposed = true;

        if (s_vehHandle != IntPtr.Zero)
        {
            RemoveVectoredExceptionHandler(s_vehHandle);
            s_vehHandle = IntPtr.Zero;
        }

        s_handler = null;

        if (s_regionsBuffer != IntPtr.Zero)
        {
            Marshal.FreeHGlobal(s_regionsBuffer);
            s_regionsBuffer = IntPtr.Zero;
        }

        s_regionCount = 0;
        s_active = false;
    }
}
