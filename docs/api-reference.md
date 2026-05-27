# API Reference

## Core Interfaces

### ISandboxedPlugin

The interface every plugin must implement.

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
| `Id` | Unique plugin identifier |
| `Name` | Human-readable name |
| `Version` | Semantic version string |
| `Initialize` | Called once after loading; receives the sandboxed context |
| `ExecuteAsync` | Main plugin entry point |
| `Shutdown` | Called before unloading |

### IPluginContext

The sandboxed context provided to plugins.

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
| `GetConfigValue<T>` | Read per-plugin configuration |
| `CheckCancellation` | Throw if the host has requested cancellation |
| `ReportProgress` | Report 0-100 progress to the host |
| `RequestMoreTime` | Extend execution timeout (max 5 minutes) |

---

## Services

### IFileService

File access API available to plugins.

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

HTTP access API available to plugins.

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

    // Security policy
    SecurityPolicy = new SecurityPolicy()
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

Plugins access injected services via `IPluginContext.GetService<T>()`.

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
| `EXECUTION_TIMEOUT` | Plugin exceeded time limit |
| `READ_LIMIT_EXCEEDED` | Read I/O limit exceeded |
| `WRITE_LIMIT_EXCEEDED` | Write I/O limit exceeded |
| `HTTP_LIMIT_EXCEEDED` | HTTP request limit exceeded |
| `SERVICE_NOT_FOUND` | Requested service not injected |
