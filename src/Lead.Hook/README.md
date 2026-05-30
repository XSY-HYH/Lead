# Lead.Hook

A lightweight IL-rewriting hook engine for .NET 8+ and .NET 10 — no Harmony, no runtime patching, no native hooks.

## How It Works

Lead.Hook rewrites IL instructions **at assembly load time** using Mono.Cecil. It scans target assemblies for specific IL patterns and replaces them with calls to your replacement methods — before the code ever executes.

## Supported Hook Types

| HookType | IL Instruction | Description |
|---|---|---|
| `CallSite` | `call` / `callvirt` | Redirect method calls to your replacement |
| `MethodBody` | Method IL body | Replace entire method body (works with static classes, reflection-safe) |
| `NewObj` | `newobj` | Intercept object creation, replace with factory method |
| `FieldRead` | `ldfld` / `ldsfld` | Intercept field read access |
| `FieldWrite` | `stfld` / `stsfld` | Intercept field write access |
| `TypeCheck` | `isinst` / `castclass` | Intercept `as`/`is` type checks |
| `Box` | `box` / `unbox.any` | Intercept boxing/unboxing |
| `FunctionPointer` | `ldftn` / `ldvirtftn` | Intercept function pointer acquisition |

## Quick Start

```csharp
using Lead.Hook;

var engine = new HookBuilder()
    // CallSite: redirect method call
    .Hook("MyApp.TextPrinter", "GetText")
        .With(typeof(MyReplacement), "GetText")

    // MethodBody: replace entire method body (static class safe)
    .Hook("MyApp.SecretKeeper", "GetSecret", HookType.MethodBody)
        .With(typeof(SecretReplacement), "GetSecret")

    // NewObj: intercept constructor
    .Hook("MyApp.ConfigLoader", ".ctor", HookType.NewObj)
        .With(typeof(ConfigFactory), "Create")

    // FieldRead: intercept field access
    .Hook("MyApp.UserProfile", "Name", HookType.FieldRead)
        .With(typeof(FieldHooks), "GetName")

    .Build();

var result = engine.RewriteWithResult("TargetApp.dll");
// Load result.RewrittenAssembly via AssemblyLoadContext
```

## Replacement Method Signatures

```csharp
// CallSite (instance method): first param is 'this'
public static int Add(object self, int x) => 0;

// CallSite (static method): no 'this'
public static string GetText() => "replaced";

// MethodBody: same as CallSite
public static string GetSecret() => "replaced";

// NewObj: same params as constructor, returns replacement object
public static ConfigShadow Create(string env) => new("hacked-" + env);

// FieldRead (instance): receives 'this'
public static string GetName(object self) => "replaced";

// FieldRead (static): no params
public static string GetRole() => "admin";

// FieldWrite (instance): receives 'this' + value
public static void SetName(object self, string value) { }

// FieldWrite (static): receives value
public static void SetRole(string value) { }

// TypeCheck: receives object, returns object?
public static object? CheckType(object obj) => obj;

// Box: receives value type, returns object
public static object BoxInt(int value) => value;

// Unbox: receives object, returns value type
public static int UnboxInt(object value) => (int)value;

// FunctionPointer: returns IntPtr
public static IntPtr GetPtr() => IntPtr.Zero;
```

## .NET 10 Compatibility

Lead.Hook targets `net8.0` and is fully compatible with .NET 10 applications. No known breaking issues.

## License

MIT
