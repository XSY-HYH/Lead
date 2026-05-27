# Lead

A secure, virtualized plugin sandbox for .NET 8.

Lead loads third-party assemblies into an isolated environment where every operation is controlled, monitored, or virtualized. Plugins cannot tell whether they are running in a real system or a honeypot.

## Features

- **Static Analysis** — IL-level scanning blocks unsafe code, P/Invoke, reflection, dynamic IL generation, and 40+ attack vectors before loading
- **Virtualization** — Three modes for file/HTTP access:
  - `Block` — hard deny with error codes
  - `Redirect` — transparent path/URL remapping into sandbox VFS
  - `Honeypot` — returns realistic fake data, silently logs all access
- **Service Injection** — plugins receive only the APIs you register; nothing else is accessible
- **Resource Limits** — file size, I/O throughput, HTTP request count, execution timeout
- **Custom Redirectors** — implement `IFileRedirector` / `IHttpResponder` to define your own virtualization logic

## Quick Start

```csharp
using Lead;

var config = new SandboxConfiguration
{
    SandboxRootDirectory = "./sandbox_data",
    AllowedUrlPatterns = { @"^https://api\.example\.com/.*$" },
    MaxExecutionSeconds = 30
};

// Enable honeypot mode (default) — plugins see fake data
config.UseHoneypotDefaults();

using var loader = new PluginLoader(config);

var result = await loader.LoadPluginAsync("ThirdPartyPlugin.dll");
if (result.Success)
{
    await loader.ExecutePluginAsync(result.PluginId);
    loader.UnloadPlugin(result.PluginId);
}
```

## Writing a Plugin

```csharp
using Lead;

public class MyPlugin : ISandboxedPlugin
{
    private IPluginContext? _ctx;

    public string Id => "my-plugin";
    public string Name => "My Plugin";
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

| Mode | File Access | HTTP Access | Plugin Awareness |
|------|------------|-------------|-----------------|
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
