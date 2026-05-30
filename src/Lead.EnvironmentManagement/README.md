# Lead.EnvironmentManagement

One-click preset sandbox environments for Windows and Linux — system info spoofing, file virtualization, and runtime variable inspection, built on top of [Lead.Sandbox](https://www.nuget.org/packages/Lead.Sandbox).

## Features

- **Preset Environments**: Windows/Linux sandbox with Honeypot, Block, or Redirect modes
- **System Info Spoofing**: Fake `Environment`, `RuntimeInformation` API responses
- **Linux File Virtualization**: Virtual `/proc`, `/etc` files (`cpuinfo`, `os-release`, `passwd`, etc.)
- **Runtime Inspection**: Read/write static/instance fields and properties, invoke methods on loaded assemblies

## Quick Start

```csharp
using Lead.EnvironmentManagement;

// Windows honeypot sandbox
using var sandbox = PresetSandbox.CreateWindowsHoneypot();

// Linux honeypot with custom profile
var linuxProfile = new EnvironmentProfile
{
    IsLinux = true,
    MachineName = "my-fake-host",
    ProcessorCount = 2,
    ProcessArchitecture = Architecture.Arm64,
};
using var linux = PresetSandbox.CreateLinuxHoneypot(linuxProfile);

// Load and inspect a plugin
var result = await sandbox.LoadPluginAsync("plugin.dll");
if (result.Success)
{
    var inspector = sandbox.Inspector!;
    var value = inspector.GetStaticFieldValue("MyApp.Config", "Version");
    inspector.SetStaticFieldValue("MyApp.Config", "Version", "2.0");
}
```

## Preset Environments

| Method | OS | Mode | Description |
|---|---|---|---|
| `CreateWindowsHoneypot()` | Windows | Honeypot | Allow + log all access |
| `CreateWindowsBlock()` | Windows | Block | Block file/network access |
| `CreateWindowsRedirect()` | Windows | Redirect | Redirect to sandbox directory |
| `CreateLinuxHoneypot()` | Linux | Honeypot | Allow + log + virtual `/proc`, `/etc` |
| `CreateLinuxBlock()` | Linux | Block | Block file/network access |
| `CreateLinuxRedirect()` | Linux | Redirect | Redirect to sandbox directory |

## Environment Profiles

Built-in profiles: `EnvironmentProfile.WindowsDefault`, `EnvironmentProfile.LinuxDefault`, `EnvironmentProfile.LinuxArm64`.

Custom profiles:

```csharp
var profile = new EnvironmentProfile
{
    MachineName = "fake-server",
    UserName = "admin",
    ProcessorCount = 16,
    ProcessArchitecture = Architecture.X64,
    OSArchitecture = Architecture.X64,
    OSDescriptionString = "Linux 5.15.0-generic x86_64",
    EnvironmentVariables = new() { { "CUSTOM_VAR", "value" } }
};
```

## Runtime Inspector

```csharp
var inspector = sandbox.Inspector;

// Static fields/properties
inspector.GetStaticFieldValue("Namespace.Type", "FieldName");
inspector.SetStaticFieldValue("Namespace.Type", "FieldName", value);
inspector.GetStaticPropertyValue("Namespace.Type", "PropertyName");
inspector.SetStaticPropertyValue("Namespace.Type", "PropertyName", value);

// Instance fields/properties
inspector.GetInstanceFieldValue(instance, "FieldName");
inspector.SetInstanceFieldValue(instance, "FieldName", value);
inspector.GetInstancePropertyValue(instance, "PropertyName");
inspector.SetInstancePropertyValue(instance, "PropertyName", value);

// Method invocation
inspector.InvokeStaticMethod("Namespace.Type", "MethodName", args);
inspector.InvokeInstanceMethod(instance, "MethodName", args);
```

## License

MIT
