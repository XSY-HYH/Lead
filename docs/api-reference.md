# API Reference

## Core Concepts

Lead is an assembly sandbox, not a plugin framework. Its primary purpose is to **load and execute any .NET assembly safely**, regardless of whether the code is trusted. `ISandboxedPlugin` is an optional interface for structured lifecycle management — assemblies without it can still be loaded and invoked.

---

## Loading & Execution

### PluginLoader

The main entry point for loading and executing assemblies.

```csharp
using var loader = new PluginLoader(config);

// Load any .NET DLL
var result = await loader.LoadPluginAsync("SomeLibrary.dll");

if (result.Success)
{
    if (result.IsRawAssembly)
    {
        // No ISandboxedPlugin — invoke methods directly
        var output = await loader.InvokeMethodAsync(
            result.PluginId,
            "Namespace.ClassName",
            "MethodName",
            new object[] { arg1, arg2 }
        );

        // Or access the Assembly for reflection
        var assembly = loader.GetLoadedAssembly(result.PluginId);
    }
    else
    {
        // Implements ISandboxedPlugin — use structured execution
        await loader.ExecutePluginAsync(result.PluginId);
    }

    loader.UnloadPlugin(result.PluginId);
}
```

| Method | Description |
|--------|-------------|
| `LoadPluginAsync(path)` | Load any .NET assembly; returns `LoadResult` with validation info |
| `ExecutePluginAsync(id)` | Execute a loaded `ISandboxedPlugin` assembly |
| `InvokeMethodAsync(id, type, method, args)` | Invoke a method by name on a loaded assembly |
| `GetLoadedAssembly(id)` | Get the `Assembly` object for reflection |
| `GetHookRewriteCount()` | Get number of IL rewrites applied during loading |
| `UnloadPlugin(id)` | Unload and collect the assembly |

### LoadResult

```csharp
public class LoadResult
{
    public bool Success { get; init; }
    public string PluginId { get; init; }
    public string? Error { get; init; }
    public ISandboxedPlugin? Plugin { get; init; }        // null if IsRawAssembly
    public ValidationResult? Validation { get; init; }     // always populated
    public bool IsRawAssembly { get; init; }               // true if no ISandboxedPlugin
}
```

- `IsRawAssembly == true` → assembly loaded but does not implement `ISandboxedPlugin`
- `Validation` → always contains static analysis results (advisory by default)
- `Plugin != null` → assembly implements `ISandboxedPlugin`, can use `ExecutePluginAsync`

---

## Runtime IL Rewriting (Hook Engine)

Lead's hook engine rewrites IL method calls at load time using Mono.Cecil. When an assembly calls `File.Delete(path)`, the `call` instruction is rewritten to `FileIOProxy.Delete(path)`. No Harmony, no native hooks — pure managed IL rewriting.

### IMethodHook

Define custom hook rules by implementing this interface.

```csharp
public interface IMethodHook
{
    string Category { get; }
    IEnumerable<MethodHookRule> GetRules();
}
```

### MethodHookRule

A single hook rule: original method → proxy method.

```csharp
public class MethodHookRule
{
    public string OriginalType { get; }      // e.g. "System.IO.File"
    public string OriginalMethod { get; }    // e.g. "Delete"
    public Type ProxyType { get; }           // e.g. typeof(FileIOProxy)
    public string ProxyMethod { get; }       // e.g. "Delete"
    public string? Description { get; }
}
```

### MethodHookDispatcher

Manages all hook rules and provides lookup.

```csharp
var dispatcher = new MethodHookDispatcher();
dispatcher.Register(new FileIOMethodHook());
dispatcher.Register(new[] { new ProcessMethodHook(), new ReflectionMethodHook() });

// Lookup
var rule = dispatcher.FindRule("System.IO.File", "Delete");
var allRules = dispatcher.GetAllRules();
var fileRules = dispatcher.GetRulesByCategory("FileIO");
```

### RuntimeHookManager

Core engine that performs IL rewriting. Called automatically by `PluginLoader` when `EnableRuntimeHooks = true`.

```csharp
var manager = new RuntimeHookManager(dispatcher);
var rewrittenBytes = manager.RewriteAssembly("plugin.dll");
// or
var rewrittenBytes = manager.RewriteAssembly(originalBytes);

int count = manager.RewriteCount;  // number of call instructions rewritten
```

### Built-in Hooks

| Hook Class | Category | Methods Hooked |
|------------|----------|---------------|
| `FileIOMethodHook` | FileIO | `File.Delete`, `File.ReadAllText`, `File.ReadAllBytes`, `File.WriteAllText`, `File.WriteAllBytes`, `File.Exists`, `File.ReadLines`, `File.AppendAllText` |
| `AssemblyLoadFromMethodHook` | AssemblyLoading | `Assembly.LoadFrom`, `Assembly.Load` |
| `NetworkMethodHook` | Network | `HttpClient.GetStringAsync` |
| `ProcessMethodHook` | Process | `Process.Start`, `Process.Kill` |
| `ReflectionMethodHook` | Reflection | `MethodInfo.Invoke`, `Activator.CreateInstance` |

### Proxy Classes

| Proxy | Behavior by Mode |
|-------|-----------------|
| `FileIOProxy` | Block: throws; Redirect: maps to VFS; Honeypot: returns fake data / silently records |
| `AssemblyLoadFromProxy` | Loads through sandbox ALC with IL rewriting; can be disabled via `AllowAssemblyLoadFrom = false` |
| `NetworkProxy` | Block: throws; Honeypot: returns fake HTTP response |
| `ProcessProxy` | Block: throws; Honeypot: silently records (no process spawned) |
| `ReflectionProxy` | Block: throws; Honeypot: returns null |

Each proxy exposes a `GetAccessLog()` / `GetRequestLog()` method for auditing.

### Custom Hook Example

```csharp
using Lead.Hooks;

public class RegistryHook : IMethodHook
{
    public string Category => "Registry";

    public IEnumerable<MethodHookRule> GetRules()
    {
        yield return new MethodHookRule(
            "Microsoft.Win32.Registry", "GetValue",
            typeof(RegistryProxy), "GetValue",
            "Hook Registry.GetValue to return fake data"
        );
    }
}

// Register
config.HookDispatcher.Register(new RegistryHook());
```

---

## Optional Interface

### ISandboxedPlugin

Optional interface for assemblies that want structured lifecycle management and service injection.

```csharp
public interface ISandboxedPlugin
{
    string Id { get; }
    string Name { get; }
    string Version { get; }
    void Initialize(IPluginContext context);
    Task ExecuteAsync(CancellationToken cancellationToken);
    void Shutdown();
}
```

### IPluginContext

The sandboxed context provided to `ISandboxedPlugin` implementations.

```csharp
public interface IPluginContext
{
    T? GetService<T>() where T : class;
    bool HasService<T>() where T : class;
    T GetConfigValue<T>(string key, T defaultValue = default!);
    bool HasConfig(string key);
    void CheckCancellation();
    void ReportProgress(int percentage);
    void RequestMoreTime(TimeSpan additionalTime);
    event EventHandler<int> ProgressReported;
}
```

---

## Services

### IFileService

File access API available to loaded code.

```csharp
public interface IFileService
{
    Task<string> ReadTextFileAsync(string path, CancellationToken ct = default);
    Task WriteTextFileAsync(string path, string content, CancellationToken ct = default);
    Task<byte[]> ReadBinaryFileAsync(string path, CancellationToken ct = default);
    Task WriteBinaryFileAsync(string path, byte[] data, CancellationToken ct = default);
    bool FileExists(string path);
    bool DirectoryExists(string path);
    IEnumerable<string> GetFiles(string directory, string pattern = "*");
}
```

### IHttpService

HTTP access API available to loaded code.

```csharp
public interface IHttpService
{
    Task<string> HttpGetAsync(string url, Dictionary<string, string>? headers = null, CancellationToken ct = default);
    Task<string> HttpPostAsync(string url, string body, string contentType = "application/json", CancellationToken ct = default);
}
```

---

## Virtualization

### IFileRedirector

Customize file virtualization behavior.

```csharp
public interface IFileRedirector
{
    string? RedirectPath(string originalPath);
    string? GetVirtualContent(string path);
    byte[]? GetVirtualBinaryContent(string path);
    bool VirtualFileExists(string path);
    bool VirtualDirectoryExists(string path);
    IEnumerable<string> GetVirtualFiles(string directory, string pattern);
    void RecordWrite(string path, string content);
    void RecordWrite(string path, byte[] data);
    void RecordAccess(string path, string operation);
}
```

### VirtualFileRedirector

Default implementation with built-in virtual files for common system paths.

```csharp
var redirector = new VirtualFileRedirector();
redirector.AddVirtualFile(@"C:\Secret\db.txt", "connection string here");
redirector.AddVirtualBinaryFile(@"C:\Secret\key.pem", keyBytes);
redirector.AddPathMapping(@"C:\Secret", "secret");
var log = redirector.GetAccessLog();
```

### IHttpResponder

Customize HTTP response behavior.

```csharp
public interface IHttpResponder
{
    Task<string> GetResponseAsync(string url, string method, string? body = null, Dictionary<string, string>? headers = null);
    void RecordRequest(string url, string method, string? body, Dictionary<string, string>? headers);
}
```

### HoneypotHttpResponder

Default implementation with built-in fake responses for cloud metadata endpoints.

```csharp
var responder = new HoneypotHttpResponder();
responder.AddResponder("http://internal-api/users", fakeJson);
responder.AddResponder("http://internal-api/admin", resp => GenerateFakeResponse());
var log = responder.GetRequestLog();
```

---

## Configuration

### SandboxConfiguration

```csharp
var config = new SandboxConfiguration
{
    // File system
    SandboxRootDirectory = "./sandbox_data",
    AllowedFileExtensions = { ".txt", ".json", ".csv" },
    ReadOnlyMode = false,

    // Resource limits
    MaxExecutionSeconds = 30,
    MaxFileSize = 10 * 1024 * 1024,
    MaxBytesRead = 100 * 1024 * 1024,
    MaxBytesWritten = 50 * 1024 * 1024,
    MaxHttpRequests = 100,
    HttpTimeoutSeconds = 10,

    // HTTP
    AllowedUrlPatterns = { @"^https://api\.example\.com/.*$" },

    // Virtualization
    FileRedirectMode = RedirectMode.Honeypot,
    FileRedirector = new VirtualFileRedirector(),
    HttpRedirectMode = RedirectMode.Honeypot,
    HttpResponder = new HoneypotHttpResponder(),
    HttpRedirectTargets = new() { [@"^http://evil\.com/"] = "https://safe-sink.example.com/log" },

    // Runtime hooks
    EnableRuntimeHooks = true,
    AllowAssemblyLoadFrom = true,
    // HookDispatcher is pre-populated by UseHoneypotDefaults() etc.
    // Add custom hooks: config.HookDispatcher.Register(new MyHook());

    // Security
    SecurityPolicy = new SecurityPolicy(),
    StrictValidation = false
};
```

### Preset Configurations

```csharp
config.UseHoneypotDefaults();   // Honeypot mode + default hooks + default redirectors
config.UseRedirectDefaults();   // Redirect mode + default hooks + default redirectors
config.UseBlockDefaults();      // Block mode + default hooks
```

All presets enable `EnableRuntimeHooks = true` and register the five built-in hooks (FileIO, AssemblyLoading, Network, Process, Reflection).

### Service Injection

```csharp
config.RegisterService<IMyService>(new MyServiceImpl());
```

---

## Security

### SecurityPolicy

Controls static analysis rules.

```csharp
var policy = new SecurityPolicy();
policy.AddForbiddenType("System.Diagnostics.Process");
policy.AddForbiddenMethod("System.IO.File.Delete");
policy.AddForbiddenAttribute("System.Runtime.InteropServices.StructLayoutAttribute");
```

Default forbidden categories:
- Unsafe code and pointers
- P/Invoke and native interop
- Reflection (MethodInfo.Invoke, Activator, etc.)
- Dynamic IL generation (DynamicMethod, AssemblyBuilder)
- Process spawning
- Direct file I/O (File.Delete, File.ReadAllText, etc.)
- Direct HTTP (HttpClient constructors)
- Registry access
- StructLayout / FieldOffset / UnmanagedCallersOnly
- MemoryMarshal reinterpret operations
- Thread pool manipulation

### StrictValidation

| Value | Behavior |
|-------|----------|
| `false` (default) | Static analysis is advisory; assemblies load regardless; `LoadResult.Validation` contains findings |
| `true` | Assemblies with validation errors are rejected and will not load |

### RedirectMode

```csharp
public enum RedirectMode
{
    Block,      // Throw SandboxException
    Redirect,   // Transparently remap to sandbox
    Honeypot    // Return fake data, log everything
}
```

### Error Codes

| Code | Description |
|------|-------------|
| `FORBIDDEN_TYPE` | Type blocked by security policy |
| `FORBIDDEN_METHOD` | Method blocked by security policy |
| `FORBIDDEN_ATTRIBUTE` | Attribute blocked by security policy |
| `FORBIDDEN_ASSEMBLY` | Assembly blocked by ALC |
| `UNSAFE_CODE` | Unsafe code detected |
| `PINVOKE` | P/Invoke call detected |
| `PATH_TRAVERSAL` | Path traversal attempt |
| `PATH_ESCAPE` | Path escaped sandbox boundary |
| `FORBIDDEN_FILE_EXT` | File extension not allowed |
| `FORBIDDEN_URL` | URL not in whitelist |
| `PRIVATE_IP` | Private/internal IP address |
| `FORBIDDEN_PROTOCOL` | Non-HTTP protocol |
| `FILE_TOO_LARGE` | File exceeds size limit |
| `EXECUTION_TIMEOUT` | Execution exceeded time limit |
| `READ_LIMIT_EXCEEDED` | Read I/O limit exceeded |
| `WRITE_LIMIT_EXCEEDED` | Write I/O limit exceeded |
| `HTTP_LIMIT_EXCEEDED` | HTTP request limit exceeded |
| `SERVICE_NOT_FOUND` | Requested service not injected |
| `PLUGIN_NOT_FOUND` | Plugin ID not found |
| `PLUGIN_TYPE_NOT_FOUND` | Type not found in loaded assembly |
| `PLUGIN_LOAD_FAILED` | General load failure |
