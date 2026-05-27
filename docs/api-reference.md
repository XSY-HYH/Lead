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

| Member | Description |
|--------|-------------|
| `Id` | Unique identifier |
| `Name` | Human-readable name |
| `Version` | Semantic version string |
| `Initialize` | Called once after loading; receives the sandboxed context |
| `ExecuteAsync` | Main entry point |
| `Shutdown` | Called before unloading |

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

| Member | Description |
|--------|-------------|
| `GetService<T>` | Retrieve an injected service (e.g. `IFileService`, `IHttpService`) |
| `HasService<T>` | Check if a service is available |
| `GetConfigValue<T>` | Read per-assembly configuration |
| `CheckCancellation` | Throw if the host has requested cancellation |
| `ReportProgress` | Report 0-100 progress to the host |
| `RequestMoreTime` | Extend execution timeout (max 5 minutes) |

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

Behavior depends on `RedirectMode`:

| Mode | Relative path | Absolute/traversal path |
|------|--------------|------------------------|
| `Block` | Normal sandbox I/O | Throws `PATH_TRAVERSAL` |
| `Redirect` | Normal sandbox I/O | Remapped to VFS |
| `Honeypot` | Normal sandbox I/O | Returns fake data, logs access |

### IHttpService

HTTP access API available to loaded code.

```csharp
public interface IHttpService
{
    Task<string> HttpGetAsync(string url, Dictionary<string, string>? headers = null, CancellationToken ct = default);
    Task<string> HttpPostAsync(string url, string body, string contentType = "application/json", CancellationToken ct = default);
}
```

Behavior depends on `RedirectMode`:

| Mode | Whitelisted URL | Non-whitelisted/private URL |
|------|----------------|---------------------------|
| `Block` | Real HTTP request | Throws `FORBIDDEN_URL` / `PRIVATE_IP` |
| `Redirect` | Real HTTP request | Redirected to safe target or fake response |
| `Honeypot` | Real HTTP request | Returns fake response, logs request |

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

// Add custom virtual files
redirector.AddVirtualFile(@"C:\Secret\db.txt", "connection string here");
redirector.AddVirtualBinaryFile(@"C:\Secret\key.pem", keyBytes);

// Add path mappings (for Redirect mode)
redirector.AddPathMapping(@"C:\Secret", "secret");

// Audit access log
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

// Add custom responses
responder.AddResponder("http://internal-api/users", fakeJson);
responder.AddResponder("http://internal-api/admin", resp => GenerateFakeResponse());

// Audit request log
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
    MaxFileSize = 10 * 1024 * 1024,        // 10 MB
    MaxBytesRead = 100 * 1024 * 1024,       // 100 MB
    MaxBytesWritten = 50 * 1024 * 1024,     // 50 MB
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

    // Security
    SecurityPolicy = new SecurityPolicy(),
    StrictValidation = false    // true = reject unsafe assemblies; false = advisory only
};
```

### Preset Configurations

```csharp
config.UseHoneypotDefaults();   // Honeypot mode with default redirectors
config.UseRedirectDefaults();   // Redirect mode with default redirectors
config.UseBlockDefaults();      // Block mode (hard deny)
```

### Service Injection

```csharp
config.RegisterService<IMyService>(new MyServiceImpl());
```

`ISandboxedPlugin` implementations access injected services via `IPluginContext.GetService<T>()`.

---

## Security

### SecurityPolicy

Controls static analysis rules.

```csharp
var policy = new SecurityPolicy();

// Customize forbidden types/methods/attributes
policy.AddForbiddenType("System.Diagnostics.Process");
policy.AddForbiddenMethod("System.Reflection.MethodInfo.Invoke");
policy.AddForbiddenAttribute("System.Runtime.InteropServices.StructLayoutAttribute");
```

Default forbidden categories:
- Unsafe code and pointers
- P/Invoke and native interop
- Reflection (MethodInfo.Invoke, Activator, etc.)
- Dynamic IL generation (DynamicMethod, AssemblyBuilder)
- Process spawning
- StructLayout / FieldOffset / UnmanagedCallersOnly
- MemoryMarshal reinterpret operations
- Thread pool manipulation

### StrictValidation

By default (`StrictValidation = false`), static analysis results are **advisory** — assemblies load regardless of violations, and `LoadResult.Validation` contains the findings for the host to review.

When `StrictValidation = true`, assemblies with validation errors are **rejected** and will not load.

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

All errors use string codes, not numeric values:

| Code | Description |
|------|-------------|
| `FORBIDDEN_TYPE` | Type blocked by security policy |
| `FORBIDDEN_METHOD` | Method blocked by security policy |
| `FORBIDDEN_ATTRIBUTE` | Attribute blocked by security policy |
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
