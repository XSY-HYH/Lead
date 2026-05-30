using System.Reflection;
using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;

namespace Lead.Hook.Runtime;

internal static class NativeMemory
{
    [DllImport("kernel32.dll")]
    private static extern bool VirtualProtect(IntPtr lpAddress, UIntPtr dwSize, uint flNewProtect, out uint lpflOldProtect);

    private const uint PAGE_EXECUTE_READWRITE = 0x40;

    public static bool MakeWritable(IntPtr address, int size)
    {
        if (Environment.OSVersion.Platform == PlatformID.Win32NT)
            return VirtualProtect(address, (UIntPtr)size, PAGE_EXECUTE_READWRITE, out _);
        return true;
    }
}

internal static class JitHelper
{
    public static IntPtr GetNativeCode(MethodInfo method)
    {
        RuntimeHelpers.PrepareMethod(method.MethodHandle);
        return ResolveRealEntryPoint(method.MethodHandle.GetFunctionPointer());
    }

    public static void ForceCompile(MethodInfo method)
    {
        RuntimeHelpers.PrepareMethod(method.MethodHandle);
    }

    private static IntPtr ResolveRealEntryPoint(IntPtr funcPtr)
    {
        try
        {
            var bytes = new byte[16];
            Marshal.Copy(funcPtr, bytes, 0, 16);

            if (bytes[0] == 0xFF && bytes[1] == 0x25)
            {
                var offset = BitConverter.ToInt32(bytes, 2);
                var targetAddr = Marshal.ReadIntPtr(funcPtr + 6 + offset);
                if (targetAddr != IntPtr.Zero)
                    return targetAddr;
            }
        }
        catch
        {
        }

        return funcPtr;
    }
}

internal sealed class RuntimePatcher
{
    private readonly List<RuntimePatch> _patches = new();

    public IReadOnlyList<RuntimePatch> Patches => _patches;

    public RuntimePatch PatchMethod(MethodInfo original, MethodInfo replacement)
    {
        JitHelper.ForceCompile(original);
        JitHelper.ForceCompile(replacement);

        var originalPtr = JitHelper.GetNativeCode(original);
        var replacementPtr = JitHelper.GetNativeCode(replacement);

        if (originalPtr == IntPtr.Zero || replacementPtr == IntPtr.Zero)
            throw new InvalidOperationException($"Cannot get native entry point. Original: {originalPtr}, Replacement: {replacementPtr}");

        var originalBytes = BackupBytes(originalPtr, 32);

        if (!NativeMemory.MakeWritable(originalPtr, 32))
            throw new InvalidOperationException("Failed to make original method memory writable");

        WriteAbsoluteJump(originalPtr, replacementPtr);

        var patch = new RuntimePatch(original, replacement, originalPtr, replacementPtr, originalBytes);
        _patches.Add(patch);
        return patch;
    }

    public bool Unpatch(RuntimePatch patch)
    {
        if (!_patches.Contains(patch))
            return false;

        RestoreBytes(patch.OriginalEntry, patch.OriginalBytes);
        _patches.Remove(patch);
        return true;
    }

    public void UnpatchAll()
    {
        foreach (var patch in _patches.ToList())
            RestoreBytes(patch.OriginalEntry, patch.OriginalBytes);
        _patches.Clear();
    }

    private static void WriteAbsoluteJump(IntPtr from, IntPtr to)
    {
        var jumpBytes = new byte[14];
        jumpBytes[0] = 0xFF;
        jumpBytes[1] = 0x25;
        jumpBytes[2] = 0x00;
        jumpBytes[3] = 0x00;
        jumpBytes[4] = 0x00;
        jumpBytes[5] = 0x00;
        BitConverter.TryWriteBytes(jumpBytes.AsSpan(6, 8), to.ToInt64());

        Marshal.Copy(jumpBytes, 0, from, 14);
    }

    private static byte[] BackupBytes(IntPtr address, int count)
    {
        var bytes = new byte[count];
        Marshal.Copy(address, bytes, 0, count);
        return bytes;
    }

    private static void RestoreBytes(IntPtr address, byte[] bytes)
    {
        if (!NativeMemory.MakeWritable(address, bytes.Length))
            throw new InvalidOperationException("Failed to make memory writable for restore");
        Marshal.Copy(bytes, 0, address, bytes.Length);
    }
}

public sealed class RuntimePatch
{
    public MethodInfo Original { get; }
    public MethodInfo Replacement { get; }
    public IntPtr OriginalEntry { get; }
    public IntPtr ReplacementEntry { get; }
    public byte[] OriginalBytes { get; }

    public RuntimePatch(MethodInfo original, MethodInfo replacement, IntPtr originalEntry, IntPtr replacementEntry, byte[] originalBytes)
    {
        Original = original;
        Replacement = replacement;
        OriginalEntry = originalEntry;
        ReplacementEntry = replacementEntry;
        OriginalBytes = originalBytes;
    }

    public override string ToString() => $"[RuntimePatch] {Original.DeclaringType?.Name}::{Original.Name} → {Replacement.DeclaringType?.Name}::{Replacement.Name}";
}
