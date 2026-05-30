# Lead.Hook

A dual-mode hook engine for .NET 8+ and .NET 10 — IL rewriting at load time **and** runtime native patching, no Harmony required.

## Dual-Mode Architecture

| Mode | When | How | Undo |
|---|---|---|---|
| **ILRewrite** | Before assembly loads | Mono.Cecil rewrites IL instructions | N/A (permanent for loaded assembly) |
| **RuntimePatch** | After methods are JIT-compiled | Overwrites native code entry with `jmp [rip+addr]` | Fully reversible via `Unpatch()` |

## IL Rewriting — Supported Hook Types

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

## Quick Start — IL Rewriting

```csharp
using Lead.Hook;

var engine = new HookBuilder()
    .Hook("MyApp.TextPrinter", "GetText")
        .With(typeof(MyReplacement), "GetText")

    .Hook("MyApp.SecretKeeper", "GetSecret", HookType.MethodBody)
        .With(typeof(SecretReplacement), "GetSecret")

    .Hook("MyApp.ConfigLoader", ".ctor", HookType.NewObj)
        .With(typeof(ConfigFactory), "Create")

    .Hook("MyApp.UserProfile", "Name", HookType.FieldRead)
        .With(typeof(FieldHooks), "GetName")

    .Build();

var result = engine.RewriteWithResult("TargetApp.dll");
```

## Quick Start — Runtime Patching

```csharp
using Lead.Hook;

using var runtime = new RuntimeHookEngine();

// Patch a static method
runtime.Patch(typeof(MyClass).GetMethod("StaticMethod")!,
              typeof(MyReplacement).GetMethod("StaticMethod")!);

// Patch an instance method (replacement receives 'this' as first param)
runtime.Patch(typeof(MyClass).GetMethod("InstanceMethod")!,
              typeof(MyReplacement).GetMethod("InstanceMethod")!);

// Now calls to MyClass.StaticMethod() and obj.InstanceMethod() are redirected

// Unpatch a specific method
runtime.Unpatch(typeof(MyClass).GetMethod("StaticMethod")!);

// Unpatch all
runtime.UnpatchAll();
```

## Mixed Mode — IL Rewrite + Runtime Patch

```csharp
var engine = new HookBuilder()
    // IL rewrite rules (applied at assembly load)
    .Hook("MyApp.TextPrinter", "GetText")
        .With(typeof(MyReplacement), "GetText")

    // Runtime patch rules (applied to already-loaded methods)
    .Hook("MyApp.LiveService", "Process", HookType.CallSite, PatchMode.RuntimePatch)
        .With(typeof(LiveReplacement), "Process")

    .Build();

// IL rewrite happens here
var result = engine.RewriteWithResult("TargetApp.dll");

// Runtime patches are applied automatically for PatchMode.RuntimePatch rules
// Access runtime engine directly:
engine.ApplyRuntimePatch("MyApp.AnotherType", "Method", typeof(Replacement), "Method");
engine.RemoveRuntimePatch("MyApp.AnotherType", "Method");
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

## Runtime Patching — How It Works

1. Forces JIT compilation of both original and replacement methods via `RuntimeHelpers.PrepareMethod`
2. Resolves the real native entry point by following the PreJitStub indirect jump
3. Backs up the original method's native code
4. Writes an absolute jump to the replacement method
5. On unpatch: restores the original bytes

**Platform Support:**

| Platform | Memory Protection | Jump Encoding | Status |
|---|---|---|---|
| Windows x64 | `VirtualProtect` | `FF 25 00 00 00 00 <addr>` | Tested |
| Linux x64 | `mprotect` | `FF 25 00 00 00 00 <addr>` | Supported |
| macOS x64 | `mprotect` | `FF 25 00 00 00 00 <addr>` | Supported |
| Linux ARM64 | `mprotect` | `LDR X16, [PC]; BR X16` | Supported |
| macOS ARM64 | `mprotect` | `LDR X16, [PC]; BR X16` | Supported |

**Limitations:**
- Methods must be JIT-compiled before patching (call them once first)
- Tiered Compilation may re-JIT methods, potentially overwriting patches

## .NET 10 Compatibility

Lead.Hook targets `net8.0` and is fully compatible with .NET 10 applications. No known breaking issues.

## License

MIT
