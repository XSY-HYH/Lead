# Lead

A secure, virtualized assembly sandbox for .NET 8+.

Lead loads **any** .NET assembly — including unsafe, P/Invoke, or unmanaged code — into an isolated environment where every operation is controlled, monitored, or virtualized. Loaded code cannot tell whether it is running in a real system or a honeypot.

## Why Lead?

.NET 10 currently lacks mature hook frameworks and embeddable sandbox solutions. Existing options either don't support .NET 10, require runtime instrumentation that breaks across framework versions, or provide only hard-deny isolation that malicious code can detect and evade.

Lead solves this by providing a pure managed-code sandbox that works on .NET 8+ and .NET 10 out of the box — no native hooks, no runtime patching, no framework-specific dependencies. The honeypot virtualization model makes loaded code believe it is operating on a real system while all data is fake and all access is logged.

## Features

- **Load Any Assembly** — no interface requirement, no format restriction; load any .NET DLL and execute it safely
- **Static Analysis** — IL-level scanning detects unsafe code, P/Invoke, reflection, dynamic IL generation, and 40+ attack vectors; results are advisory by default, blockable via `StrictValidation`
- **Runtime IL Rewriting** — self-built hook engine rewrites method calls at load time; `File.Delete` becomes `FileIOProxy.Delete`, `Process.Start` becomes `ProcessProxy.Start` — no Harmony, no native hooks, fully compatible with .NET 10
- **Runtime Isolation** — `AssemblyLoadContext` blocks native DLL loading, restricts dangerous system assemblies, and isolates loaded code dependencies
- **Virtualization** — Three modes for file/HTTP access:
  - `Block` — hard deny with error codes
  - `Redirect` — transparent path/URL remapping into sandbox VFS
  - `Honeypot` — returns realistic fake data, silently logs all access
- **Service Injection** — loaded code receives only the APIs you register; nothing else is accessible
- **Resource Limits** — file size, I/O throughput, HTTP request count, execution timeout
- **Custom Redirectors** — implement `IFileRedirector` / `IHttpResponder` to define your own virtualization logic
- **Custom Hooks** — implement `IMethodHook` to define your own IL rewriting rules

## Quick Start

### Load and Execute Any DLL

```csharp
using Lead;

var config = new SandboxConfiguration
{
    SandboxRootDirectory = "./sandbox_data",
    AllowedUrlPatterns = { @"^https://api\.example\.com/.*$" },
    MaxExecutionSeconds = 30
};

config.UseHoneypotDefaults();

using var loader = new PluginLoader(config);

var result = await loader.LoadPluginAsync("SomeUnsafeLibrary.dll");
// result.IsRawAssembly == true — no ISandboxedPlugin interface found
// result.Validation contains static analysis warnings (not errors)

if (result.Success)
{
    // Invoke a specific method by name
    var output = await loader.InvokeMethodAsync(
        result.PluginId,
        typeName: "SomeNamespace.SomeClass",
        methodName: "ProcessData",
        args: new object[] { "input" }
    );

    // Or get the Assembly for reflection
    var assembly = loader.GetLoadedAssembly(result.PluginId);

    loader.UnloadPlugin(result.PluginId);
}
```

### Load an ISandboxedPlugin (Optional Interface)

If the assembly implements `ISandboxedPlugin`, Lead will automatically initialize and execute it:

```csharp
var result = await loader.LoadPluginAsync("MyLibrary.dll");
if (result.Success && result.Plugin != null)
{
    await loader.ExecutePluginAsync(result.PluginId);
    loader.UnloadPlugin(result.PluginId);
}
```

### Strict Mode (Block Unsafe Code)

```csharp
var config = new SandboxConfiguration
{
    StrictValidation = true  // reject assemblies with unsafe code
};
```

## Runtime IL Rewriting

Lead's hook engine rewrites IL at load time using Mono.Cecil. When an assembly calls `File.Delete(path)`, the IL `call` instruction is rewritten to call `FileIOProxy.Delete(path)` instead. The proxy then decides what to do based on the current `RedirectMode`.

**No Harmony, no native hooks, no runtime patching** — pure managed IL rewriting, fully compatible with .NET 10.

### Built-in Hooks

| Category | Original Method | Proxy Method | Effect (Honeypot) |
|----------|----------------|-------------|-------------------|
| FileIO | `File.Delete` | `FileIOProxy.Delete` | Silently recorded, no real deletion |
| FileIO | `File.ReadAllText` | `FileIOProxy.ReadAllText` | Returns fake file content |
| FileIO | `File.WriteAllText` | `FileIOProxy.WriteAllText` | Silently recorded |
| FileIO | `File.Exists` | `FileIOProxy.Exists` | Returns virtual file existence |
| AssemblyLoading | `Assembly.LoadFrom` | `AssemblyLoadFromProxy.LoadFrom` | Loads through sandbox ALC with IL rewriting |
| AssemblyLoading | `Assembly.Load` | `AssemblyLoadFromProxy.Load` | Loads through sandbox ALC, checks blocked prefixes |
| Network | `HttpClient.GetStringAsync` | `NetworkProxy.GetStringAsync` | Returns fake HTTP response |
| Process | `Process.Start` | `ProcessProxy.Start` | Silently recorded, no process spawned |
| Process | `Process.Kill` | `ProcessProxy.Kill` | Silently recorded |
| Reflection | `MethodInfo.Invoke` | `ReflectionProxy.Invoke` | Returns null |
| Reflection | `Activator.CreateInstance` | `ReflectionProxy.CreateInstance` | Returns null or default |

### Custom Hook

```csharp
using Lead.Hooks;

public class MyCustomHook : IMethodHook
{
    public string Category => "Custom";

    public IEnumerable<MethodHookRule> GetRules()
    {
        yield return new MethodHookRule(
            "System.IO.File", "Copy",           // original method
            typeof(MyProxy), "CopyFile",         // replacement method
            "Hook File.Copy to sandbox VFS"
        );
    }
}

// Register
config.HookDispatcher.Register(new MyCustomHook());
config.EnableRuntimeHooks = true;
```

### Disable Hooks

```csharp
var config = new SandboxConfiguration
{
    EnableRuntimeHooks = false  // disable IL rewriting
};
```

### Control Assembly.LoadFrom

```csharp
var config = new SandboxConfiguration
{
    AllowAssemblyLoadFrom = false  // block Assembly.LoadFrom / Assembly.Load entirely
};
```

When `AllowAssemblyLoadFrom = true` (default), `Assembly.LoadFrom` and `Assembly.Load` calls from sandboxed code are redirected to `AssemblyLoadFromProxy`, which loads the new assembly through the same sandbox ALC with IL rewriting applied. This ensures that dynamically loaded assemblies inherit the sandbox restrictions and cannot bypass the hook engine.

## Implementing ISandboxedPlugin (Optional)

`ISandboxedPlugin` is an optional interface. Assemblies that implement it gain access to injected services and structured lifecycle management. Assemblies without this interface can still be loaded and invoked via `InvokeMethodAsync`.

```csharp
using Lead;

public class MyLibrary : ISandboxedPlugin
{
    private IPluginContext? _ctx;

    public string Id => "my-library";
    public string Name => "My Library";
    public string Version => "1.0.0";

    public void Initialize(IPluginContext context) => _ctx = context;

    public async Task ExecuteAsync(CancellationToken ct)
    {
        var fs = _ctx!.GetService<IFileService>();
        var content = await fs!.ReadTextFileAsync("data.txt", ct);
    }

    public void Shutdown() { }
}
```

## Redirect Modes

| Mode | File Access | HTTP Access | Loaded Code Awareness |
|------|------------|-------------|----------------------|
| `Block` | Throws `SandboxException` | Throws `SandboxException` | Knows it's sandboxed |
| `Redirect` | Remapped to sandbox VFS | Remapped to safe URL | Unaware |
| `Honeypot` | Returns fake data + logs | Returns fake response + logs | Unaware |

## Custom Virtualization

```csharp
// Custom virtual files
var redirector = new VirtualFileRedirector();
redirector.AddVirtualFile(@"C:\Secret\db.txt", "host=10.0.0.1;password=honey");
config.FileRedirector = redirector;

// Custom HTTP responses
var responder = new HoneypotHttpResponder();
responder.AddResponder("http://internal-api/users", "[{\"id\":1,\"name\":\"John\"}]");
config.HttpResponder = responder;

// Or implement your own
config.FileRedirector = new MyCustomRedirector();
config.HttpResponder = new MyCustomResponder();
```

## License

MIT

---

## Lead.EnvironmentManagement

A companion package that provides one-click preset sandboxes and runtime inspection capabilities on top of Lead.Sandbox.

### Install

```
dotnet add package Lead.EnvironmentManagement
```

### One-Click Preset Sandboxes

No manual configuration needed — choose your platform and mode:

```csharp
using Lead.EnvironmentManagement;

// Windows Honeypot
using var sandbox = PresetSandbox.CreateWindowsHoneypot();
var result = await sandbox.LoadPluginAsync("plugin.dll");

// Linux Honeypot (spoofs /etc/passwd, /proc/cpuinfo, etc.)
using var sandbox = PresetSandbox.CreateLinuxHoneypot();

// Linux ARM64 (spoofs architecture to Arm64)
using var sandbox = PresetSandbox.CreateLinuxHoneypot(EnvironmentProfile.LinuxArm64);

// Block mode variants
using var sandbox = PresetSandbox.CreateWindowsBlock();
using var sandbox = PresetSandbox.CreateLinuxBlock();

// Redirect mode variants
using var sandbox = PresetSandbox.CreateWindowsRedirect();
using var sandbox = PresetSandbox.CreateLinuxRedirect();
```

### System Info Spoofing

Loaded code sees a completely fake environment:

- `Environment.MachineName` → `DESKTOP-SANDBOX` (Windows) / `sandbox-host` (Linux)
- `Environment.UserName` → `sandbox_user`
- `RuntimeInformation.OSArchitecture` → `X64` or `Arm64`
- `RuntimeInformation.OSDescription` → Fake OS string
- `Environment.GetFolderPath(...)` → Virtual paths
- `Environment.GetEnvironmentVariable(...)` → Fake env vars

Custom profiles:

```csharp
var profile = new EnvironmentProfile
{
    MachineName = "my-fake-host",
    UserName = "fake_user",
    ProcessorCount = 2,
    // ... all properties customizable
};
using var sandbox = PresetSandbox.CreateLinuxHoneypot(profile);
```

### Runtime Inspector

Inspect and manipulate loaded assemblies at runtime:

```csharp
using var sandbox = PresetSandbox.CreateWindowsHoneypot();
var result = await sandbox.LoadPluginAsync("plugin.dll");

var inspector = sandbox.Inspector;

// List types
var types = inspector.GetLoadedTypes();

// Read/write static fields
inspector.SetStaticFieldValue("MyClass", "ConfigPath", "/fake/path");
var value = inspector.GetStaticFieldValue("MyClass", "ConfigPath");

// Read/write static properties
inspector.SetStaticPropertyValue("MyClass", "Enabled", true);

// Get all variables at once
var allValues = inspector.GetAllStaticValues("MyClass");

// Invoke methods
var output = inspector.InvokeStaticMethod("MyClass", "Process", "input");

// Create instances and inspect instance fields
var instance = inspector.CreateInstance("MyClass");
inspector.SetInstanceFieldValue(instance, "_counter", 42);
var instanceValues = inspector.GetAllInstanceValues(instance);
```
