using System.Reflection;
using System.Runtime.Loader;

namespace Lead.Hooks.Proxies;

public static class AssemblyLoadFromProxy
{
    internal static bool Allowed { get; set; } = true;
    internal static SandboxedAssemblyLoadContext? CurrentContext { get; set; }
    internal static RuntimeHookManager? HookManager { get; set; }
    internal static SecurityPolicy? Policy { get; set; }

    private static readonly List<string> LoadLog = new();

    public static Assembly LoadFrom(string assemblyFile)
    {
        RecordLoad(assemblyFile);

        if (!Allowed)
            throw new SandboxException(ErrorCode.ForbiddenAssembly);

        if (CurrentContext == null)
            throw new SandboxException(ErrorCode.PluginLoadFailed);

        return CurrentContext.LoadWithRewrite(assemblyFile);
    }

    public static Assembly LoadFrom(byte[] rawAssembly)
    {
        RecordLoad($"[bytes:{rawAssembly.Length}]");

        if (!Allowed)
            throw new SandboxException(ErrorCode.ForbiddenAssembly);

        if (CurrentContext == null)
            throw new SandboxException(ErrorCode.PluginLoadFailed);

        if (HookManager != null)
        {
            try
            {
                var rewritten = HookManager.RewriteAssembly(rawAssembly);
                using var stream = new MemoryStream(rewritten);
                return CurrentContext.LoadFromStream(stream);
            }
            catch
            {
                using var stream = new MemoryStream(rawAssembly);
                return CurrentContext.LoadFromStream(stream);
            }
        }

        using var ms = new MemoryStream(rawAssembly);
        return CurrentContext.LoadFromStream(ms);
    }

    public static Assembly Load(string assemblyString)
    {
        RecordLoad(assemblyString);

        if (!Allowed)
            throw new SandboxException(ErrorCode.ForbiddenAssembly);

        if (CurrentContext == null)
            throw new SandboxException(ErrorCode.PluginLoadFailed);

        var asmName = new AssemblyName(assemblyString);

        if (Policy != null)
        {
            if (Policy.BlockedAssemblyPrefixes.Any(b => asmName.Name?.StartsWith(b) == true))
                throw new SandboxException(ErrorCode.ForbiddenAssembly);
        }

        return CurrentContext.LoadFromAssemblyName(asmName);
    }

    private static void RecordLoad(string target)
    {
        LoadLog.Add($"[{DateTime.Now:HH:mm:ss}] ASSEMBLY_LOAD -> {target}");
    }

    public static IReadOnlyList<string> GetLoadLog() => LoadLog.AsReadOnly();
}
