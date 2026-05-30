# Security Testing Log

This document records all attack vectors that have been tested against Lead, along with their outcomes. The goal is to provide transparency about what Lead can and cannot defend against.

> **Terminology**: "blocked" means the attack was successfully prevented or mitigated. "leaked" means the attack succeeded in performing its intended malicious operation. A vector may have been "blocked" in earlier versions and later enhanced to block more thoroughly — each row reflects the current state.

---

## Defensive Capabilities (Blocked)

The following attack vectors have been tested and are currently blocked by Lead's security layers.

### Static Analysis (IL Scanning)

| Attack Vector | Severity | Defense Layer | Status |
|--------------|----------|---------------|--------|
| `[StructLayout(LayoutKind.Explicit)]` field overlap | High | `AssemblyValidator` — `StructLayoutAttribute` in `ForbiddenAttributes` | Blocked |
| `DynamicMethod` IL generation | Critical | `AssemblyValidator` — `DynamicMethod` in `ForbiddenTypes` + ALC blocks `System.Reflection.Emit` | Blocked |
| `ILGenerator.Emit` dynamic code | Critical | `AssemblyValidator` — `ILGenerator` in `ForbiddenTypes` + ALC blocks Emit assemblies | Blocked |
| `AssemblyBuilder` runtime assembly creation | Critical | `AssemblyValidator` — `AssemblyBuilder` in `ForbiddenTypes` | Blocked |
| `UnmanagedCallersOnly` unmanaged export | High | `AssemblyValidator` — `UnmanagedCallersOnlyAttribute` in `ForbiddenAttributes` | Blocked |
| `DllImport` P/Invoke native code | Critical | `AssemblyValidator` — detects `DllImport` attribute + `IsPInvokeImpl` check | Blocked |
| `MemoryMarshal.Cast` type punning | High | `AssemblyValidator` — `MemoryMarshal.Cast` in `ForbiddenMethods` + IL rewriting | Blocked |
| `MemoryMarshal.AsBytes` span reinterpretation | High | `AssemblyValidator` — `MemoryMarshal.AsBytes` in `ForbiddenMethods` + IL rewriting | Blocked |
| `MemoryMarshal.GetReference` pointer access | High | `AssemblyValidator` — `MemoryMarshal.GetReference` in `ForbiddenMethods` | Blocked |
| `MemoryMarshal.Read` / `Write` raw memory | High | `AssemblyValidator` — `MemoryMarshal.Read/Write` in `ForbiddenMethods` | Blocked |
| `Activator.CreateInstance` dynamic instantiation | Medium | `AssemblyValidator` — `Activator.CreateInstance` in `ForbiddenMethods` + IL rewriting | Blocked |
| `MethodInfo.Invoke` reflection execution | High | `AssemblyValidator` — `MethodInfo.Invoke` in `ForbiddenMethods` + `ReflectionProxy` at runtime | Blocked |
| `FileStream` constructor direct file access | Medium | `AssemblyValidator` — `FileStream..ctor` in `ForbiddenMethods` | Blocked |
| `StreamWriter` / `StreamReader` constructors | Medium | `AssemblyValidator` — `StreamWriter..ctor`/`StreamReader..ctor` in `ForbiddenMethods` | Blocked |
| `WebClient` constructor HTTP access | Medium | `AssemblyValidator` — `WebClient..ctor` in `ForbiddenMethods` | Blocked |
| `HttpClient` constructor HTTP access | Medium | `AssemblyValidator` — `HttpClient..ctor` in `ForbiddenMethods` | Blocked |
| `RegistryKey.OpenSubKey` registry read | Medium | `AssemblyValidator` — registry methods in `ForbiddenMethods` | Blocked |
| `Process.Start` / `Process.Kill` | Critical | ALC blocks `System.Diagnostics.Process` assembly + IL rewriting via `ProcessProxy` | Blocked |
| `AppDomain` manipulation | Critical | `AssemblyValidator` — `AppDomain` methods in `ForbiddenMethods` | Blocked |
| `calli` indirect unmanaged call via function pointer | Critical | `AssemblyValidator` — `OpCodes.Calli` detected as `UNMANAGED_CALL` error | Blocked |
| `ldftn` / `ldvirtftn` function pointer extraction | Critical | `AssemblyValidator` — `OpCodes.Ldftn` / `OpCodes.Ldvirtftn` detected as `UNMANAGED_CALL` error | Blocked |
| `NativeLibrary.Load` / `GetExport` dynamic native function resolution | Critical | `AssemblyValidator` — `NativeLibrary` in `ForbiddenTypes` + `ForbiddenMethods` + `NativeInteropProxy` at runtime | Blocked |
| `Marshal.GetDelegateForFunctionPointer` delegate-from-pointer creation | Critical | `AssemblyValidator` — `Marshal` in `ForbiddenTypes` + `ForbiddenMethods` + `NativeInteropProxy` at runtime | Blocked |

### Runtime Isolation (ALC)

| Attack Vector | Severity | Defense Layer | Status |
|--------------|----------|---------------|--------|
| Loading `System.Reflection.Emit` | Critical | ALC — `BlockedSystemAssemblies` contains `System.Reflection.Emit.*` | Blocked |
| Loading `Microsoft.Win32.Registry` | High | ALC — `BlockedSystemAssemblies` contains `Microsoft.Win32.Registry` | Blocked |
| Loading `System.Net.Sockets` | High | ALC — `BlockedSystemAssemblies` contains `System.Net.Sockets` | Blocked |
| Loading `System.IO.FileSystem.Watcher` | Medium | ALC — `BlockedSystemAssemblies` contains `System.IO.FileSystem.Watcher` | Blocked |
| Loading `System.Diagnostics.Process` | Critical | ALC — `BlockedSystemAssemblies` contains `System.Diagnostics.Process` | Blocked |
| Unmanaged DLL loading (`LoadLibrary`) | Critical | `LoadUnmanagedDll` returns `IntPtr.Zero` | Blocked |

### Runtime IL Rewriting (Hook Engine)

When `EnableRuntimeHooks = true` (default), Lead rewrites IL `call` / `callvirt` instructions at load time to redirect dangerous methods to proxy stubs. This provides defense-in-depth even when static analysis is advisory-only (`StrictValidation = false`).

| Original Call | Proxy | Honeypot Effect | Status |
|--------------|-------|-----------------|--------|
| `File.Delete(path)` | `FileIOProxy.Delete` | Silently recorded, no deletion occurs | Blocked |
| `File.ReadAllText(path)` | `FileIOProxy.ReadAllText` | Returns fake/virtual file content | Blocked |
| `File.ReadAllBytes(path)` | `FileIOProxy.ReadAllBytes` | Returns fake binary content | Blocked |
| `File.WriteAllText(path, content)` | `FileIOProxy.WriteAllText` | Silently recorded, not written to real filesystem | Blocked |
| `File.WriteAllBytes(path, data)` | `FileIOProxy.WriteAllBytes` | Silently recorded | Blocked |
| `File.Exists(path)` | `FileIOProxy.Exists` | Returns virtual file existence | Blocked |
| `File.ReadLines(path)` | `FileIOProxy.ReadLines` | Returns fake content split by newlines | Blocked |
| `File.AppendAllText(path, content)` | `FileIOProxy.AppendAllText` | Silently recorded | Blocked |
| `Assembly.LoadFrom(path)` | `AssemblyLoadFromProxy.LoadFrom` | Loads through sandbox ALC with IL rewriting; can be disabled via `AllowAssemblyLoadFrom = false` | Blocked |
| `Assembly.Load(assemblyName)` | `AssemblyLoadFromProxy.Load` | Loads through sandbox ALC; blocked assembly prefixes checked | Blocked |
| `Process.Start(fileName, arguments)` | `ProcessProxy.Start` | Silently recorded, returns null | Blocked |
| `Process.Start(fileName)` | `ProcessProxy.Start` | Silently recorded, returns null | Blocked |
| `Process.Start(startInfo)` | `ProcessProxy.Start` | Silently recorded, returns null | Blocked |
| `HttpClient.GetStringAsync(url)` | `NetworkProxy.GetStringAsync` | Returns fake HTTP response | Blocked |
| `Process.Start()` | `ProcessProxy.Start` | Silently recorded, no process spawned | Blocked |
| `Process.Kill()` | `ProcessProxy.Kill` | Silently recorded | Blocked |
| `MethodInfo.Invoke(mi, obj, args)` | `ReflectionProxy.Invoke` | Returns `null` | Blocked |
| `Activator.CreateInstance(type, args)` | `ReflectionProxy.CreateInstance` | Returns `null` or default | Blocked |
| `NativeLibrary.Load(libraryPath)` | `NativeInteropProxy.Load` | Returns `IntPtr.Zero`, no native library loaded | Blocked |
| `NativeLibrary.GetExport(handle, name)` | `NativeInteropProxy.GetExport` | Returns `IntPtr.Zero`, no function pointer obtained | Blocked |
| `NativeLibrary.Free(handle)` | `NativeInteropProxy.Free` | Silently recorded | Blocked |
| `NativeLibrary.TryLoad(...)` | `NativeInteropProxy.TryLoad` | Returns `false`, handle set to `IntPtr.Zero` | Blocked |
| `NativeLibrary.TryGetExport(...)` | `NativeInteropProxy.TryGetExport` | Returns `false`, procAddress set to `IntPtr.Zero` | Blocked |
| `Marshal.GetDelegateForFunctionPointer(ptr, type)` | `NativeInteropProxy.GetDelegateForFunctionPointer` | Returns `null`, no delegate created | Blocked |
| `Marshal.GetFunctionPointerForDelegate(d)` | `NativeInteropProxy.GetFunctionPointerForDelegate` | Returns `IntPtr.Zero` | Blocked |

### Virtualization + Service Layer

| Attack Vector | Severity | Defense Layer | Status |
|--------------|----------|---------------|--------|
| Path traversal (`../../../etc/passwd`) via `IFileService` | High | `SandboxFileService` — resolves to absolute, validates within sandbox root | Blocked |
| Absolute path access (`C:\Windows\win.ini`) via `IFileService` | Medium | `SandboxFileService` — redirected to VFS or blocked based on `RedirectMode` | Blocked |
| Forbidden file extension (`.exe`, `.dll`) via `IFileService` | Medium | `SandboxFileService` — checks `AllowedFileExtensions` | Blocked |
| SSRF cloud metadata (`169.254.169.254`) via `IHttpService` | High | `SandboxHttpService` — blocks known cloud metadata IPs | Blocked |
| SSRF localhost (`127.0.0.1`, `localhost`) via `IHttpService` | High | `SandboxHttpService` — blocks private IP ranges | Blocked |
| SSRF internal network (`10.x.x.x`, `192.168.x.x`) via `IHttpService` | High | `SandboxHttpService` — blocks private IP ranges | Blocked |
| Non-HTTP protocol (`ftp://`, `file://`) via `IHttpService` | Medium | `SandboxHttpService` — only `http://` and `https://` allowed | Blocked |
| Non-whitelisted URL via `IHttpService` | Medium | `SandboxHttpService` — validates against `AllowedUrlPatterns` | Blocked |
| File size limit bypass (write > `MaxFileSize`) | Medium | `SandboxFileService` — checks size before write | Blocked |
| Read I/O limit bypass (`MaxBytesRead`) | Medium | `SandboxFileService` — tracks cumulative bytes read | Blocked |
| Write I/O limit bypass (`MaxBytesWritten`) | Medium | `SandboxFileService` — tracks cumulative bytes written | Blocked |
| HTTP request limit (`MaxHttpRequests`) | Medium | `SandboxHttpService` — counts requests per session | Blocked |
| Execution timeout (`MaxExecutionSeconds`) | Medium | `PluginLoader` — uses `CancellationToken` + timeout task | Blocked |
| Thread pool exhaustion (`Task.Delay` flood) | Medium | `CancellationToken` propagation + timeout | Blocked |

---

### TamperGuard (Anti-Tamper Defense)

TamperGuard protects Lead's own critical methods from runtime modification. When activated, it monitors protected method memory regions and terminates the process immediately upon detecting any tampering attempt — no polling, no delay.

| Attack Vector | Severity | Defense Layer | Status |
|--------------|----------|---------------|--------|
| RuntimePatch dynamic method redirection | Critical | VEH + PAGE_EXECUTE_READ protection | Blocked |
| `Marshal.WriteByte` direct memory write | Critical | VEH catches ACCESS_VIOLATION on protected page | Blocked |
| `RtlMoveMemory` kernel32 memory copy | Critical | VEH catches ACCESS_VIOLATION on protected page | Blocked |
| `NtProtectVirtualMemory` bypass API hook to change page protection | Critical | API Hook on NtProtectVirtualMemory blocks region overlap | Blocked |
| Restore VirtualProtect hook original bytes then write | Critical | Guard Page + Hardware Breakpoints detect page attribute change | Blocked |
| `unsafe` pointer direct write | Critical | VEH catches ACCESS_VIOLATION on protected page | Blocked |
| `VirtualProtectEx` cross-process page modification | Critical | API Hook on VirtualProtectEx blocks region overlap | Blocked |
| `WriteProcessMemory` remote memory write | Critical | API Hook on WriteProcessMemory blocks region overlap | Blocked |
| Reflection tamper of TamperGuard static fields | High | Critical state stored in unmanaged memory (`s_statePtr`), reflection cannot modify | Blocked |
| `RemoveVectoredExceptionHandler` remove VEH handler | High | Guard Page + Hardware Breakpoints provide redundant defense after VEH removal | Blocked |
| Direct syscall `NtProtectVirtualMemory` to change page protection then write | Critical | Hardware Breakpoints (DR0-DR3) detect write at CPU level; Guard Page triggers GUARD_PAGE_VIOLATION | Blocked |
| Clear `s_hwBreakpointsActive` flag then syscall write | High | Guard Page still protects; flag stored in unmanaged memory | Blocked |
| Multi-threaded race: parallel syscall + write | Critical | Hardware Breakpoints apply per-thread via DR registers; Guard Page is process-wide | Blocked |
| `SetThreadContext` clear DR0-DR3 registers then syscall write | Critical | Guard Page + PAGE_EXECUTE_READ protection remain after DR clearing | Blocked |
| Direct syscall `NtWriteVirtualMemory` to write protected memory | Critical | Guard Page triggers on write access; Hardware Breakpoints detect write | Blocked |
| Remove VEH then syscall change page protection (double attack) | Critical | Guard Page + Hardware Breakpoints provide defense-in-depth after VEH removal | Blocked |
| Overwrite NtProtectVirtualMemory trampoline then call original | High | Guard Page protects trampoline memory; Hardware Breakpoints detect write to trampoline | Blocked |

#### TamperGuard Defense Layers

| Layer | Mechanism | What It Catches |
|-------|-----------|-----------------|
| Page Protection | Set method memory pages to `PAGE_EXECUTE_READ` | Any direct write to protected memory (ACCESS_VIOLATION) |
| VEH Handler | Vectored Exception Handler catches access violations | Write attempts to read-only pages |
| API Hooks | Hook VirtualProtect/VirtualProtectEx/WriteProcessMemory/NtProtectVirtualMemory | Attempts to change page protection or write to protected regions via Win32 API |
| Hardware Breakpoints | DR0-DR3 write breakpoints on protected page starts | Syscall-level write attempts (CPU hardware detection) |
| Guard Page | `PAGE_GUARD` flag on protected pages | Any access to guarded pages triggers exception |
| Integrity Check | djb2 hash of method entry bytes, verified on SINGLE_STEP | Any undetected modification of method entry code |
| Unmanaged State | Critical data stored in unmanaged memory via `Marshal.AllocHGlobal` | Reflection-based tampering of TamperGuard internal state |
| FLS Recursion Guard | Fiber Local Storage flag prevents hook recursion | Hook installation triggering itself |

#### TamperGuard Configuration

```csharp
var config = new SandboxConfiguration
{
    EnableTamperProtection = true,       // Enable TamperGuard (default: true)
    EnableHardwareBreakpoints = true,    // DR register write breakpoints (default: true)
    EnableIntegrityCheck = true,         // Method entry hash verification (default: true)
    EnableGuardPage = true               // PAGE_GUARD protection (default: true)
};
```

---

## Known Limitations (Currently Leaked)

These are attack vectors that Lead **cannot currently defend against** in the managed code sandbox. Some have OS-level mitigations available (seccomp, AppArmor, containers) that are outside Lead's scope.

### Fundamental .NET Managed Sandboxing Limitations

| Attack Vector | Severity | Reason | Mitigation |
|--------------|----------|--------|------------|
| Raw socket creation via `Socket` constructor with address family `AddressFamily.InterNetwork` / `InterNetworkV6` | High | ALC blocks `System.Net.Sockets`, but raw IP sockets are a kernel-level construct; a determined attacker could potentially bypass managed sockets and interact with the network stack directly | OS-level network filtering (firewall rules, seccomp) |
| Thread pool saturation via async file I/O (not `Task.Run`) | Low | `File.ReadAllBytesAsync` / `File.WriteAllBytesAsync` use the thread pool internally; Lead cannot limit thread pool threads consumed by async I/O operations | OS-level process resource limits |
| Kernel-level attacks (rootkits, drivers) | Critical | TamperGuard operates in user space; kernel-level code can modify process memory without triggering any user-space defense | OS-level kernel security, secure boot |

### Not Yet Hooked (Potential Gaps)

| Attack Vector | Severity | Status |
|--------------|----------|--------|
| `Directory.*` methods (`Directory.Delete`, `Directory.GetFiles`, `Directory.CreateDirectory`) | Medium | ALC blocks `System.IO.FileSystem` assembly which contains `Directory`; however some directory operations may work through `File` static methods which are hooked |
| `RegistryKey.SetValue` / `CreateSubKey` | Medium | ALC blocks the Registry assembly entirely; if blocked assembly is bypassed, only `GetValue` / `OpenSubKey` are in `ForbiddenMethods`, not `SetValue` / `CreateSubKey` |
| `WebRequest.Create` (legacy HTTP stack) | Medium | `WebRequest` type is in `System` assembly (not blocked by ALC); `WebRequest.Create` is not in `ForbiddenMethods`; however the modern `HttpClient` path is blocked |
| `ProcessThread` manipulation | Low | ALC blocks `System.Diagnostics.Process`, but `ProcessThread` is a separate type not explicitly forbidden |

---

## Attack Vectors Blocked by AssemblyLoadContext (Not Hooked)

These assemblies are blocked at the ALC level — Lead refuses to load them at all. This means any code path that requires these assemblies will throw `SandboxException` (`FORBIDDEN_ASSEMBLY`) before any method-level hook or static scan runs. They are listed here for completeness; they are blocked, but not via the hook engine.

- `Microsoft.Win32.Registry` — Registry access
- `System.Diagnostics.Process` — Process spawning
- `System.Diagnostics.EventLog` — Windows event log
- `System.Diagnostics.TraceSource` — Diagnostics tracing
- `System.Net.Sockets` — Raw network sockets
- `System.Net.HttpListener` — HTTP listener
- `System.IO.Pipes` — Named pipes
- `System.IO.FileSystem.Watcher` — Filesystem watching
- `System.Runtime.InteropServices.RuntimeInformation` — Runtime introspection
- `System.Reflection.Emit` / `.ILGeneration` / `.Lightweight` — Dynamic IL generation
- `System.Security.Permissions` / `.AccessControl` / `.Principal` — Security attributes

---

## Testing Methodology

All attack vectors are tested via `MaliciousPlugin.dll` — a dedicated test library containing implementations of each attack pattern. Tests are run against both the static analyzer and the runtime sandbox with `RedirectMode.Honeypot` enabled.

- **Static analysis tests**: `AssemblyValidator.Validate()` run against `MaliciousPlugin.dll`
- **Runtime tests**: `PluginLoader` loads `MaliciousPlugin.dll` in Honeypot mode, each `ISandboxedPlugin` subclass executes its attack, results observed via proxy access logs and behavior
- **Hook rewrite tests**: `RuntimeHookManager.RewriteCount` checked after loading; `FileIOProxy.GetAccessLog()` examined to confirm redirects

---

## Changelog

| Version | Change |
|---------|--------|
| 1.0.0 | Initial release — static analysis + ALC isolation + Honeypot VFS |
| 1.0.1 | Repository URL correction, description update |
| 1.0.2 | Runtime IL rewriting hook engine added — `File.Delete`, `File.ReadAllText`, `HttpClient.GetStringAsync`, `Process.Start`, `MethodInfo.Invoke` now have dedicated runtime hooks via IL rewriting |
| 1.0.3 | `Assembly.LoadFrom` / `Assembly.Load` interception — new assemblies loaded via these APIs are redirected through the sandbox ALC with IL rewriting applied; `AllowAssemblyLoadFrom` configuration switch added; `ResolveProxyMethod` now matches by parameter count to support method overloads; `ProcessProxy.Start` and `NetworkProxy.GetStringAsync` overload support added |
| 1.0.4 | Honeypot mode verification fix — test code now uses `FileInfo`/`FileStream` (not hooked by IL rewriting) to verify real filesystem state; confirmed `File.WriteAllText` / `File.ReadAllText` / `File.Delete` are correctly virtualized in Honeypot mode; `AssemblyLoadFromMethodHook` added to default hooks; `ImportType` fallback for system types; `LoadWithRewrite` no longer silently falls back on rewrite failure |
| 1.1.4 | `Environment` / `RuntimeInformation` system info spoofing via `EnvironmentMethodHook` + `EnvironmentProxy`; Linux preset sandbox with `LinuxFileIOMethodHook` + `LinuxFileIOProxy` (virtual `/etc/*`, `/proc/*`, `/var/log/*`); `RuntimeInspector` for runtime variable read/write/invocation; `PresetSandbox` one-click factory methods for Windows/Linux Honeypot/Block/Redirect; `InternalsVisibleTo` for `Lead.EnvironmentManagement` |
| 1.1.5 | `calli` / `ldftn` / `ldvirtftn` IL instruction detection as `UNMANAGED_CALL`; `NativeInteropMethodHook` + `NativeInteropProxy` for `NativeLibrary.Load/GetExport/Free/TryLoad/TryGetExport` and `Marshal.GetDelegateForFunctionPointer/GetFunctionPointerForDelegate`; `Marshal` memory manipulation methods added to `ForbiddenMethods` |
| 1.2.0 | `TamperGuard` anti-tamper defense — VEH exception handler + API hooks (VirtualProtect/VirtualProtectEx/WriteProcessMemory/NtProtectVirtualMemory) + hardware breakpoints (DR0-DR3) + Guard Page (PAGE_GUARD) + method entry integrity check (djb2 hash); unmanaged state storage; FLS recursion guard; 17 attack scenarios tested with 100% defense rate including direct syscall, DR register clearing, multi-threaded race, and trampoline overwrite attacks; `SandboxConfiguration` new properties: `EnableHardwareBreakpoints`, `EnableIntegrityCheck`, `EnableGuardPage` |
