using System.Reflection;
using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;

namespace Lead.Security;

public sealed class TamperGuard : IDisposable
{
    private const uint PAGE_EXECUTE_READ = 0x20;
    private const uint PAGE_EXECUTE_READWRITE = 0x40;
    private const uint PAGE_GUARD = 0x100;
    private const int STATUS_ACCESS_VIOLATION = unchecked((int)0xC0000005);
    private const int STATUS_GUARD_PAGE_VIOLATION = unchecked((int)0x80000001);
    private const int STATUS_SINGLE_STEP = unchecked((int)0x80000004);
    private const long EXCEPTION_CONTINUE_SEARCH = 0;
    private const long EXCEPTION_CONTINUE_EXECUTION = unchecked((long)0xFFFFFFFF);

    [DllImport("kernel32.dll")]
    private static extern bool VirtualProtect(IntPtr lpAddress, UIntPtr dwSize, uint flNewProtect, out uint lpflOldProtect);

    [DllImport("kernel32.dll")]
    private static extern IntPtr AddVectoredExceptionHandler(uint first, IntPtr handler);

    [DllImport("kernel32.dll")]
    private static extern int RemoveVectoredExceptionHandler(IntPtr handle);

    [DllImport("kernel32.dll")]
    private static extern IntPtr GetModuleHandle(string lpModuleName);

    [DllImport("kernel32.dll")]
    private static extern IntPtr GetProcAddress(IntPtr hModule, string lpProcName);

    [DllImport("kernel32.dll")]
    private static extern bool TerminateProcess(IntPtr hProcess, uint uExitCode);

    [DllImport("kernel32.dll")]
    private static extern uint FlsAlloc(IntPtr callback);

    [DllImport("kernel32.dll")]
    private static extern bool FlsSetValue(uint dwFlsIndex, IntPtr lpFlsData);

    [DllImport("kernel32.dll")]
    private static extern IntPtr FlsGetValue(uint dwFlsIndex);

    [DllImport("kernel32.dll")]
    private static extern IntPtr CreateToolhelp32Snapshot(uint dwFlags, uint th32ProcessID);

    [DllImport("kernel32.dll")]
    private static extern bool Thread32First(IntPtr hSnapshot, ref THREADENTRY32 lppe);

    [DllImport("kernel32.dll")]
    private static extern bool Thread32Next(IntPtr hSnapshot, ref THREADENTRY32 lppe);

    [DllImport("kernel32.dll")]
    private static extern IntPtr OpenThread(uint dwDesiredAccess, bool bInheritHandle, uint dwThreadId);

    [DllImport("kernel32.dll")]
    private static extern bool GetThreadContext(IntPtr hThread, ref CONTEXT lpContext);

    [DllImport("kernel32.dll")]
    private static extern bool SetThreadContext(IntPtr hThread, ref CONTEXT lpContext);

    [DllImport("kernel32.dll")]
    private static extern bool CloseHandle(IntPtr hObject);

    [DllImport("kernel32.dll")]
    private static extern uint GetCurrentProcessId();

    [DllImport("kernel32.dll")]
    private static extern uint GetCurrentThreadId();

    [DllImport("libc")]
    private static extern int mprotect(IntPtr addr, UIntPtr len, int prot);

    private const int PROT_READ = 0x1;
    private const int PROT_EXEC = 0x4;

    private const uint TH32CS_SNAPTHREAD = 0x00000004;
    private const uint THREAD_SET_CONTEXT = 0x0010;
    private const uint THREAD_GET_CONTEXT = 0x0008;
    private const uint THREAD_SUSPEND_RESUME = 0x0002;
    private const uint THREAD_QUERY_INFORMATION = 0x0040;

    private const int CONTEXT_DEBUG_REGISTERS = 0x00010000;
    private const int CONTEXT_AMD64 = 0x00100000;

    [StructLayout(LayoutKind.Sequential)]
    private struct THREADENTRY32
    {
        public uint dwSize;
        public uint cntUsage;
        public uint th32ThreadID;
        public uint th32OwnerProcessID;
        public int tpBasePri;
        public int tpDeltaPri;
        public uint dwFlags;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct CONTEXT
    {
        public int ContextFlags;
        public uint P1Home, P2Home, P3Home, P4Home, P5Home, P6Home;
        public int ContextFlags2;
        public uint MxCsr;
        public ushort SegCs, SegDs, SegEs, SegFs, SegGs, SegSs;
        public uint EFlags;
        public ulong Dr0, Dr1, Dr2, Dr3, Dr6, Dr7;
        public ulong Rax, Rcx, Rdx, Rbx, Rsp, Rbp, Rsi, Rdi;
        public ulong R8, R9, R10, R11, R12, R13, R14, R15;
        public ulong Rip;
        public ulong FltSave0, FltSave1, FltSave2, FltSave3, FltSave4, FltSave5, FltSave6, FltSave7;
        public ulong FltSave8, FltSave9, FltSave10, FltSave11, FltSave12, FltSave13, FltSave14, FltSave15;
        public ulong Vector0, Vector1, Vector2, Vector3, Vector4, Vector5, Vector6, Vector7;
        public ulong Vector8, Vector9, Vector10, Vector11, Vector12, Vector13, Vector14, Vector15;
        public ulong DebugControl, LastBranchToRip, LastBranchFromRip, LastExceptionToRip, LastExceptionFromRip;
    }

    [UnmanagedFunctionPointer(CallingConvention.StdCall)]
    private delegate long VectoredHandlerDelegate(IntPtr exceptionPointers);

    [UnmanagedFunctionPointer(CallingConvention.StdCall)]
    private delegate bool VirtualProtectDelegate(IntPtr lpAddress, UIntPtr dwSize, uint flNewProtect, out uint lpflOldProtect);

    [UnmanagedFunctionPointer(CallingConvention.StdCall)]
    private delegate bool VirtualProtectExDelegate(IntPtr hProcess, IntPtr lpAddress, UIntPtr dwSize, uint flNewProtect, out uint lpflOldProtect);

    [UnmanagedFunctionPointer(CallingConvention.StdCall)]
    private delegate bool WriteProcessMemoryDelegate(IntPtr hProcess, IntPtr lpBaseAddress, IntPtr lpBuffer, UIntPtr nSize, out IntPtr lpNumberOfBytesWritten);

    [UnmanagedFunctionPointer(CallingConvention.StdCall)]
    private delegate int NtProtectVirtualMemoryDelegate(IntPtr processHandle, ref IntPtr baseAddress, ref UIntPtr regionSize, uint newProtect, out uint oldProtect);

    private static IntPtr s_statePtr;
    private static VectoredHandlerDelegate? s_vehHandler;
    private static IntPtr s_vehHandle;
    private static bool s_active;
    private static uint s_flsIndex;

    private static IntPtr s_vpHookAddr;
    private static byte[]? s_vpOriginalBytes;
    private static VirtualProtectDelegate? s_vpHook;
    private static bool s_vpHooked;

    private static IntPtr s_vpExHookAddr;
    private static byte[]? s_vpExOriginalBytes;
    private static VirtualProtectExDelegate? s_vpExHook;
    private static bool s_vpExHooked;

    private static IntPtr s_wpmHookAddr;
    private static byte[]? s_wpmOriginalBytes;
    private static WriteProcessMemoryDelegate? s_wpmHook;
    private static bool s_wpmHooked;

    private static IntPtr s_ntpvmHookAddr;
    private static byte[]? s_ntpvmOriginalBytes;
    private static NtProtectVirtualMemoryDelegate? s_ntpvmHook;
    private static bool s_ntpvmHooked;

    private static IntPtr s_ntpvmTrampoline;
    private static NtProtectVirtualMemoryDelegate? s_ntpvmTrampolineCall;

    private static IntPtr s_hwBreakpoints;
    private static int s_hwBreakpointCount;
    private static bool s_hwBreakpointsActive;

    private static IntPtr s_integrityHashes;
    private static int s_integrityHashCount;
    private static bool s_integrityCheckEnabled;

    private static bool s_guardPageEnabled;

    private readonly List<(IntPtr Start, IntPtr End, string Name)> _pendingRegions = new();
    private readonly List<(IntPtr Entry, int ByteCount)> _pendingIntegrityChecks = new();
    private bool _disposed;

    private static int GetRegionCount()
    {
        return s_statePtr != IntPtr.Zero ? Marshal.ReadInt32(s_statePtr + 16) : 0;
    }

    private static IntPtr GetRegionsBuffer()
    {
        return s_statePtr != IntPtr.Zero ? Marshal.ReadIntPtr(s_statePtr + 8) : IntPtr.Zero;
    }

    private static bool IsRegionOverlapping(long addr, long rangeEnd)
    {
        var buf = GetRegionsBuffer();
        var count = GetRegionCount();
        if (buf == IntPtr.Zero || count == 0) return false;

        for (int i = 0; i < count; i++)
        {
            var regionStart = Marshal.ReadIntPtr(buf, i * 16).ToInt64();
            var regionEnd = Marshal.ReadIntPtr(buf, i * 16 + 8).ToInt64();
            if (addr < regionEnd && rangeEnd > regionStart)
                return true;
        }
        return false;
    }

    public TamperGuard Protect(MethodInfo method)
    {
        ObjectDisposedException.ThrowIf(_disposed, this);

        RuntimeHelpers.PrepareMethod(method.MethodHandle);
        var entry = ResolveEntryPoint(method.MethodHandle.GetFunctionPointer());

        var pageSize = Environment.SystemPageSize;
        var pageStart = (long)entry & ~(pageSize - 1);
        var pageEnd = pageStart + pageSize;

        _pendingRegions.Add(((IntPtr)pageStart, (IntPtr)pageEnd, $"{method.DeclaringType?.Name}::{method.Name}"));
        _pendingIntegrityChecks.Add((entry, 32));
        return this;
    }

    public TamperGuard EnableHardwareBreakpoints()
    {
        ObjectDisposedException.ThrowIf(_disposed, this);
        s_hwBreakpointsActive = true;
        return this;
    }

    public TamperGuard EnableIntegrityCheck()
    {
        ObjectDisposedException.ThrowIf(_disposed, this);
        s_integrityCheckEnabled = true;
        return this;
    }

    public TamperGuard EnableGuardPage()
    {
        ObjectDisposedException.ThrowIf(_disposed, this);
        s_guardPageEnabled = true;
        return this;
    }

    public void Activate()
    {
        ObjectDisposedException.ThrowIf(_disposed, this);
        if (s_active) return;

        var count = _pendingRegions.Count;
        if (count == 0) return;

        var regionsBuffer = Marshal.AllocHGlobal(count * 16);
        for (int i = 0; i < count; i++)
        {
            var (start, end, _) = _pendingRegions[i];
            Marshal.WriteIntPtr(regionsBuffer, i * 16, start);
            Marshal.WriteIntPtr(regionsBuffer, i * 16 + 8, end);
        }

        s_statePtr = Marshal.AllocHGlobal(24);
        Marshal.WriteIntPtr(s_statePtr, IntPtr.Zero);
        Marshal.WriteIntPtr(s_statePtr + 8, regionsBuffer);
        Marshal.WriteInt32(s_statePtr + 16, count);

        if (RuntimeInformation.IsOSPlatform(OSPlatform.Windows))
        {
            s_flsIndex = FlsAlloc(IntPtr.Zero);

            foreach (var (start, end, _) in _pendingRegions)
            {
                uint prot = PAGE_EXECUTE_READ;
                if (s_guardPageEnabled)
                    prot |= PAGE_GUARD;
                VirtualProtect(start, (UIntPtr)(end.ToInt64() - start.ToInt64()), prot, out _);
            }

            s_vehHandler = StaticOnVectoredException;
            s_vehHandle = AddVectoredExceptionHandler(1, Marshal.GetFunctionPointerForDelegate(s_vehHandler));

            HookAllApis();

            if (s_integrityCheckEnabled)
                StoreIntegrityHashes();

            if (s_hwBreakpointsActive)
                SetHardwareBreakpoints();
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

    private static void StoreIntegrityHashes()
    {
        var buf = GetRegionsBuffer();
        var count = GetRegionCount();
        if (buf == IntPtr.Zero || count == 0) return;

        s_integrityHashCount = count;
        s_integrityHashes = Marshal.AllocHGlobal(count * 8);

        for (int i = 0; i < count; i++)
        {
            var start = Marshal.ReadIntPtr(buf, i * 16);
            var hash = ComputeRegionHash(start, 32);
            Marshal.WriteIntPtr(s_integrityHashes, i * 8, hash);
        }
    }

    private static IntPtr ComputeRegionHash(IntPtr addr, int byteCount)
    {
        long hash = 5381;
        for (int i = 0; i < byteCount; i++)
        {
            byte b = Marshal.ReadByte(addr, i);
            hash = ((hash << 5) + hash) ^ b;
        }
        return (IntPtr)hash;
    }

    private static bool VerifyIntegrity()
    {
        if (s_integrityHashes == IntPtr.Zero || s_integrityHashCount == 0) return true;

        var buf = GetRegionsBuffer();
        for (int i = 0; i < s_integrityHashCount; i++)
        {
            var start = Marshal.ReadIntPtr(buf, i * 16);
            var stored = Marshal.ReadIntPtr(s_integrityHashes, i * 8);
            var current = ComputeRegionHash(start, 32);
            if (current != stored)
                return false;
        }
        return true;
    }

    private static void SetHardwareBreakpoints()
    {
        var buf = GetRegionsBuffer();
        var count = GetRegionCount();
        if (buf == IntPtr.Zero || count == 0) return;

        var bpCount = Math.Min(count, 4);
        s_hwBreakpointCount = bpCount;
        s_hwBreakpoints = Marshal.AllocHGlobal(bpCount * 8);

        var bpAddrs = new ulong[4];
        for (int i = 0; i < bpCount; i++)
        {
            var start = Marshal.ReadIntPtr(buf, i * 16);
            bpAddrs[i] = (ulong)start;
            Marshal.WriteIntPtr(s_hwBreakpoints, i * 8, start);
        }

        var pid = GetCurrentProcessId();
        var snap = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
        if (snap == (IntPtr)(-1)) return;

        var te = new THREADENTRY32 { dwSize = (uint)Marshal.SizeOf<THREADENTRY32>() };

        if (Thread32First(snap, ref te))
        {
            do
            {
                if (te.th32OwnerProcessID == pid)
                {
                    var hThread = OpenThread(
                        THREAD_SET_CONTEXT | THREAD_GET_CONTEXT | THREAD_SUSPEND_RESUME | THREAD_QUERY_INFORMATION,
                        false, te.th32ThreadID);
                    if (hThread == IntPtr.Zero) continue;

                    var ctx = new CONTEXT { ContextFlags = CONTEXT_DEBUG_REGISTERS | CONTEXT_AMD64 };
                    if (GetThreadContext(hThread, ref ctx))
                    {
                        for (int i = 0; i < bpCount; i++)
                        {
                            switch (i)
                            {
                                case 0: ctx.Dr0 = bpAddrs[0]; break;
                                case 1: ctx.Dr1 = bpAddrs[1]; break;
                                case 2: ctx.Dr2 = bpAddrs[2]; break;
                                case 3: ctx.Dr3 = bpAddrs[3]; break;
                            }
                        }

                        ulong dr7 = ctx.Dr7;
                        for (int i = 0; i < bpCount; i++)
                        {
                            dr7 |= (1UL << (i * 2));
                            dr7 &= ~(3UL << (16 + i * 4));
                            dr7 |= (1UL << (18 + i * 4));
                        }
                        ctx.Dr7 = dr7;

                        SetThreadContext(hThread, ref ctx);
                    }

                    CloseHandle(hThread);
                }
            } while (Thread32Next(snap, ref te));
        }

        CloseHandle(snap);
    }

    private static void ClearHardwareBreakpoints()
    {
        var pid = GetCurrentProcessId();
        var snap = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
        if (snap == (IntPtr)(-1)) return;

        var te = new THREADENTRY32 { dwSize = (uint)Marshal.SizeOf<THREADENTRY32>() };

        if (Thread32First(snap, ref te))
        {
            do
            {
                if (te.th32OwnerProcessID == pid)
                {
                    var hThread = OpenThread(
                        THREAD_SET_CONTEXT | THREAD_GET_CONTEXT | THREAD_SUSPEND_RESUME | THREAD_QUERY_INFORMATION,
                        false, te.th32ThreadID);
                    if (hThread == IntPtr.Zero) continue;

                    var ctx = new CONTEXT { ContextFlags = CONTEXT_DEBUG_REGISTERS | CONTEXT_AMD64 };
                    if (GetThreadContext(hThread, ref ctx))
                    {
                        ctx.Dr0 = ctx.Dr1 = ctx.Dr2 = ctx.Dr3 = 0;
                        ctx.Dr6 = 0;
                        ctx.Dr7 = 0;
                        SetThreadContext(hThread, ref ctx);
                    }

                    CloseHandle(hThread);
                }
            } while (Thread32Next(snap, ref te));
        }

        CloseHandle(snap);
    }

    private static bool IsInHook()
    {
        return FlsGetValue(s_flsIndex) != IntPtr.Zero;
    }

    private static void SetInHook(bool value)
    {
        FlsSetValue(s_flsIndex, value ? (IntPtr)1 : IntPtr.Zero);
    }

    private static void HookAllApis()
    {
        var kernel32 = GetModuleHandle("kernel32.dll");
        var ntdll = GetModuleHandle("ntdll.dll");

        var vpAddr = kernel32 != IntPtr.Zero ? GetProcAddress(kernel32, "VirtualProtect") : IntPtr.Zero;
        var vpExAddr = kernel32 != IntPtr.Zero ? GetProcAddress(kernel32, "VirtualProtectEx") : IntPtr.Zero;
        var wpmAddr = kernel32 != IntPtr.Zero ? GetProcAddress(kernel32, "WriteProcessMemory") : IntPtr.Zero;
        var ntpvmAddr = ntdll != IntPtr.Zero ? GetProcAddress(ntdll, "NtProtectVirtualMemory") : IntPtr.Zero;

        if (ntpvmAddr != IntPtr.Zero)
        {
            s_ntpvmHookAddr = ntpvmAddr;
            s_ntpvmOriginalBytes = new byte[14];
            Marshal.Copy(ntpvmAddr, s_ntpvmOriginalBytes, 0, 14);

            s_ntpvmTrampoline = Marshal.AllocHGlobal(64);
            RawVirtualProtect(s_ntpvmTrampoline, (UIntPtr)64, PAGE_EXECUTE_READWRITE, out _);
            Marshal.Copy(s_ntpvmOriginalBytes, 0, s_ntpvmTrampoline, 14);
            var continueJump = BuildX64Jump(ntpvmAddr.ToInt64() + 14);
            Marshal.Copy(continueJump, 0, s_ntpvmTrampoline + 14, 14);

            s_ntpvmTrampolineCall = Marshal.GetDelegateForFunctionPointer<NtProtectVirtualMemoryDelegate>(s_ntpvmTrampoline);

            s_ntpvmHook = NtProtectVirtualMemoryHook;
            InstallHook(ntpvmAddr, Marshal.GetFunctionPointerForDelegate(s_ntpvmHook));
            s_ntpvmHooked = true;
        }

        if (vpAddr != IntPtr.Zero)
        {
            s_vpHookAddr = vpAddr;
            s_vpOriginalBytes = new byte[14];
            Marshal.Copy(vpAddr, s_vpOriginalBytes, 0, 14);
            s_vpHook = VirtualProtectHook;
            InstallHook(vpAddr, Marshal.GetFunctionPointerForDelegate(s_vpHook!));
            s_vpHooked = true;
        }

        if (vpExAddr != IntPtr.Zero)
        {
            s_vpExHookAddr = vpExAddr;
            s_vpExOriginalBytes = new byte[14];
            Marshal.Copy(vpExAddr, s_vpExOriginalBytes, 0, 14);
            s_vpExHook = VirtualProtectExHook;
            InstallHook(vpExAddr, Marshal.GetFunctionPointerForDelegate(s_vpExHook!));
            s_vpExHooked = true;
        }

        if (wpmAddr != IntPtr.Zero)
        {
            s_wpmHookAddr = wpmAddr;
            s_wpmOriginalBytes = new byte[14];
            Marshal.Copy(wpmAddr, s_wpmOriginalBytes, 0, 14);
            s_wpmHook = WriteProcessMemoryHook;
            InstallHook(wpmAddr, Marshal.GetFunctionPointerForDelegate(s_wpmHook!));
            s_wpmHooked = true;
        }
    }

    private static void RawVirtualProtect(IntPtr lpAddress, UIntPtr dwSize, uint flNewProtect, out uint lpflOldProtect)
    {
        var baseAddr = lpAddress;
        var regionSize = dwSize;
        if (s_ntpvmTrampolineCall != null)
        {
            s_ntpvmTrampolineCall((IntPtr)(-1), ref baseAddr, ref regionSize, flNewProtect, out lpflOldProtect);
        }
        else
        {
            NtProtectVirtualMemoryNative((IntPtr)(-1), ref baseAddr, ref regionSize, flNewProtect, out lpflOldProtect);
        }
    }

    [DllImport("ntdll.dll", EntryPoint = "NtProtectVirtualMemory")]
    private static extern int NtProtectVirtualMemoryNative(IntPtr processHandle, ref IntPtr baseAddress, ref UIntPtr regionSize, uint newProtect, out uint oldProtect);

    private static void InstallHook(IntPtr target, IntPtr hookPtr)
    {
        RawVirtualProtect(target, (UIntPtr)14, PAGE_EXECUTE_READWRITE, out _);
        var jump = BuildX64Jump(hookPtr.ToInt64());
        Marshal.Copy(jump, 0, target, 14);
        RawVirtualProtect(target, (UIntPtr)14, PAGE_EXECUTE_READ, out _);
    }

    private static void RemoveHook(IntPtr target, byte[] originalBytes)
    {
        RawVirtualProtect(target, (UIntPtr)14, PAGE_EXECUTE_READWRITE, out _);
        Marshal.Copy(originalBytes, 0, target, 14);
        RawVirtualProtect(target, (UIntPtr)14, PAGE_EXECUTE_READ, out _);
    }

    private static bool VirtualProtectHook(IntPtr lpAddress, UIntPtr dwSize, uint flNewProtect, out uint lpflOldProtect)
    {
        if (!IsInHook() && lpAddress != IntPtr.Zero && IsRegionOverlapping(lpAddress.ToInt64(), lpAddress.ToInt64() + (long)dwSize.ToUInt64()))
            TerminateProcess((IntPtr)(-1), 0xDEAD);

        SetInHook(true);
        var baseAddr = lpAddress;
        var regionSize = dwSize;
        s_ntpvmTrampolineCall!((IntPtr)(-1), ref baseAddr, ref regionSize, flNewProtect, out lpflOldProtect);
        SetInHook(false);
        return true;
    }

    private static bool VirtualProtectExHook(IntPtr hProcess, IntPtr lpAddress, UIntPtr dwSize, uint flNewProtect, out uint lpflOldProtect)
    {
        if (!IsInHook() && lpAddress != IntPtr.Zero && IsRegionOverlapping(lpAddress.ToInt64(), lpAddress.ToInt64() + (long)dwSize.ToUInt64()))
            TerminateProcess((IntPtr)(-1), 0xDEAD);

        SetInHook(true);
        var baseAddr = lpAddress;
        var regionSize = dwSize;
        s_ntpvmTrampolineCall!(hProcess, ref baseAddr, ref regionSize, flNewProtect, out lpflOldProtect);
        SetInHook(false);
        return true;
    }

    private static bool WriteProcessMemoryHook(IntPtr hProcess, IntPtr lpBaseAddress, IntPtr lpBuffer, UIntPtr nSize, out IntPtr lpNumberOfBytesWritten)
    {
        if (!IsInHook() && lpBaseAddress != IntPtr.Zero && IsRegionOverlapping(lpBaseAddress.ToInt64(), lpBaseAddress.ToInt64() + (long)nSize.ToUInt64()))
            TerminateProcess((IntPtr)(-1), 0xDEAD);

        return DirectWriteProcessMemory(hProcess, lpBaseAddress, lpBuffer, nSize, out lpNumberOfBytesWritten);
    }

    private static int NtProtectVirtualMemoryHook(IntPtr processHandle, ref IntPtr baseAddress, ref UIntPtr regionSize, uint newProtect, out uint oldProtect)
    {
        if (!IsInHook() && baseAddress != IntPtr.Zero && IsRegionOverlapping(baseAddress.ToInt64(), baseAddress.ToInt64() + (long)regionSize.ToUInt64()))
            TerminateProcess((IntPtr)(-1), 0xDEAD);

        SetInHook(true);
        var result = s_ntpvmTrampolineCall!(processHandle, ref baseAddress, ref regionSize, newProtect, out oldProtect);
        SetInHook(false);
        return result;
    }

    [DllImport("kernel32.dll", EntryPoint = "WriteProcessMemory")]
    private static extern bool DirectWriteProcessMemory(IntPtr hProcess, IntPtr lpBaseAddress, IntPtr lpBuffer, UIntPtr nSize, out IntPtr lpNumberOfBytesWritten);

    private static byte[] BuildX64Jump(long targetAddr)
    {
        var bytes = new byte[14];
        bytes[0] = 0xFF;
        bytes[1] = 0x25;
        bytes[2] = 0x00;
        bytes[3] = 0x00;
        bytes[4] = 0x00;
        bytes[5] = 0x00;
        BitConverter.TryWriteBytes(bytes.AsSpan(6, 8), targetAddr);
        return bytes;
    }

    private static long StaticOnVectoredException(IntPtr exceptionPointers)
    {
        if (exceptionPointers == IntPtr.Zero || s_statePtr == IntPtr.Zero)
            return EXCEPTION_CONTINUE_SEARCH;

        var regionsBuffer = GetRegionsBuffer();
        var regionCount = GetRegionCount();
        if (regionsBuffer == IntPtr.Zero || regionCount == 0)
            return EXCEPTION_CONTINUE_SEARCH;

        var exceptionRecord = Marshal.ReadIntPtr(exceptionPointers);
        if (exceptionRecord == IntPtr.Zero)
            return EXCEPTION_CONTINUE_SEARCH;

        var exceptionCode = Marshal.ReadInt32(exceptionRecord);
        var ptrSize = IntPtr.Size;

        if (exceptionCode == STATUS_GUARD_PAGE_VIOLATION)
        {
            var numParamsOffset = 8 + ptrSize * 2;
            var numParams = Marshal.ReadInt32(exceptionRecord, numParamsOffset);
            if (numParams >= 2)
            {
                var infoOffset = (numParamsOffset + 4 + ptrSize - 1) & ~(ptrSize - 1);
                var writeFlagLong = Marshal.ReadIntPtr(exceptionRecord, infoOffset).ToInt64();
                if (writeFlagLong == 1)
                {
                    var faultAddress = Marshal.ReadIntPtr(exceptionRecord, infoOffset + ptrSize);

                    for (int i = 0; i < regionCount; i++)
                    {
                        var start = Marshal.ReadIntPtr(regionsBuffer, i * 16);
                        var end = Marshal.ReadIntPtr(regionsBuffer, i * 16 + 8);
                        if (faultAddress.ToInt64() >= start.ToInt64() && faultAddress.ToInt64() < end.ToInt64())
                        {
                            TerminateProcess((IntPtr)(-1), 0xDEAD);
                        }
                    }
                }
            }

            if (s_guardPageEnabled)
            {
                ReapplyGuardPages();
            }

            return EXCEPTION_CONTINUE_SEARCH;
        }

        if (exceptionCode == STATUS_SINGLE_STEP)
        {
            if (s_hwBreakpointsActive && s_hwBreakpoints != IntPtr.Zero)
            {
                var numParamsOffset = 8 + ptrSize * 2;
                var numParams = Marshal.ReadInt32(exceptionRecord, numParamsOffset);
                if (numParams >= 1)
                {
                    var infoOffset = (numParamsOffset + 4 + ptrSize - 1) & ~(ptrSize - 1);
                    var faultAddress = Marshal.ReadIntPtr(exceptionRecord, infoOffset);

                    for (int i = 0; i < s_hwBreakpointCount; i++)
                    {
                        var bpAddr = Marshal.ReadIntPtr(s_hwBreakpoints, i * 8);
                        var pageSize = Environment.SystemPageSize;
                        var bpPageStart = (IntPtr)((long)bpAddr & ~(pageSize - 1));
                        var bpPageEnd = bpPageStart.ToInt64() + pageSize;

                        if (faultAddress.ToInt64() >= bpPageStart.ToInt64() && faultAddress.ToInt64() < bpPageEnd)
                        {
                            TerminateProcess((IntPtr)(-1), 0xDEAD);
                        }
                    }
                }
            }

            if (s_integrityCheckEnabled && !VerifyIntegrity())
            {
                TerminateProcess((IntPtr)(-1), 0xDEAD);
            }

            return EXCEPTION_CONTINUE_SEARCH;
        }

        if (exceptionCode == STATUS_ACCESS_VIOLATION)
        {
            var numParamsOffset = 8 + ptrSize * 2;
            var numParams = Marshal.ReadInt32(exceptionRecord, numParamsOffset);
            if (numParams < 2)
                return EXCEPTION_CONTINUE_SEARCH;

            var infoOffset = (numParamsOffset + 4 + ptrSize - 1) & ~(ptrSize - 1);
            var writeFlagLong = Marshal.ReadIntPtr(exceptionRecord, infoOffset).ToInt64();
            if (writeFlagLong != 1)
                return EXCEPTION_CONTINUE_SEARCH;

            var faultAddress = Marshal.ReadIntPtr(exceptionRecord, infoOffset + ptrSize);

            for (int i = 0; i < regionCount; i++)
            {
                var start = Marshal.ReadIntPtr(regionsBuffer, i * 16);
                var end = Marshal.ReadIntPtr(regionsBuffer, i * 16 + 8);
                if (faultAddress.ToInt64() >= start.ToInt64() && faultAddress.ToInt64() < end.ToInt64())
                {
                    Environment.FailFast("LEAD TAMPER: write to protected method memory detected");
                }
            }
        }

        return EXCEPTION_CONTINUE_SEARCH;
    }

    private static void ReapplyGuardPages()
    {
        var buf = GetRegionsBuffer();
        var count = GetRegionCount();
        if (buf == IntPtr.Zero || count == 0) return;

        for (int i = 0; i < count; i++)
        {
            var start = Marshal.ReadIntPtr(buf, i * 16);
            var end = Marshal.ReadIntPtr(buf, i * 16 + 8);
            var size = end.ToInt64() - start.ToInt64();
            VirtualProtect(start, (UIntPtr)size, PAGE_EXECUTE_READ | PAGE_GUARD, out _);
        }
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

        if (s_hwBreakpointsActive)
        {
            ClearHardwareBreakpoints();
            s_hwBreakpointsActive = false;
        }

        if (s_hwBreakpoints != IntPtr.Zero)
        {
            Marshal.FreeHGlobal(s_hwBreakpoints);
            s_hwBreakpoints = IntPtr.Zero;
        }

        if (s_integrityHashes != IntPtr.Zero)
        {
            Marshal.FreeHGlobal(s_integrityHashes);
            s_integrityHashes = IntPtr.Zero;
            s_integrityHashCount = 0;
        }

        if (s_vpHooked && s_vpHookAddr != IntPtr.Zero && s_vpOriginalBytes != null)
        {
            RemoveHook(s_vpHookAddr, s_vpOriginalBytes);
            s_vpHooked = false;
        }
        if (s_vpExHooked && s_vpExHookAddr != IntPtr.Zero && s_vpExOriginalBytes != null)
        {
            RemoveHook(s_vpExHookAddr, s_vpExOriginalBytes);
            s_vpExHooked = false;
        }
        if (s_wpmHooked && s_wpmHookAddr != IntPtr.Zero && s_wpmOriginalBytes != null)
        {
            RemoveHook(s_wpmHookAddr, s_wpmOriginalBytes);
            s_wpmHooked = false;
        }
        if (s_ntpvmHooked && s_ntpvmHookAddr != IntPtr.Zero && s_ntpvmOriginalBytes != null)
        {
            RemoveHook(s_ntpvmHookAddr, s_ntpvmOriginalBytes);
            s_ntpvmHooked = false;
        }

        if (s_ntpvmTrampoline != IntPtr.Zero)
        {
            Marshal.FreeHGlobal(s_ntpvmTrampoline);
            s_ntpvmTrampoline = IntPtr.Zero;
        }

        s_vpHook = null;
        s_vpExHook = null;
        s_wpmHook = null;
        s_ntpvmHook = null;
        s_ntpvmTrampolineCall = null;

        if (s_vehHandle != IntPtr.Zero)
        {
            RemoveVectoredExceptionHandler(s_vehHandle);
            s_vehHandle = IntPtr.Zero;
        }

        s_vehHandler = null;

        if (s_statePtr != IntPtr.Zero)
        {
            var regionsBuffer = Marshal.ReadIntPtr(s_statePtr + 8);
            if (regionsBuffer != IntPtr.Zero)
                Marshal.FreeHGlobal(regionsBuffer);
            Marshal.FreeHGlobal(s_statePtr);
            s_statePtr = IntPtr.Zero;
        }

        s_active = false;
    }
}
