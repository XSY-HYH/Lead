using System.Reflection;
using System.Runtime.Loader;
using Lead.Hooks;

namespace Lead;

public class SandboxedAssemblyLoadContext : AssemblyLoadContext
{
    private readonly SecurityPolicy _policy;
    private readonly AssemblyDependencyResolver _resolver;
    private readonly RuntimeHookManager? _hookManager;
    private readonly Dictionary<string, byte[]> _rewrittenCache = new();

    private static readonly HashSet<string> BlockedSystemAssemblies = new(StringComparer.OrdinalIgnoreCase)
    {
        "Microsoft.Win32.Registry",
        "System.Diagnostics.Process",
        "System.Diagnostics.EventLog",
        "System.Diagnostics.TraceSource",
        "System.Net.Sockets",
        "System.Net.HttpListener",
        "System.IO.Pipes",
        "System.IO.FileSystem.Watcher",
        "System.Runtime.InteropServices.RuntimeInformation",
        "System.Reflection.Emit",
        "System.Reflection.Emit.ILGeneration",
        "System.Reflection.Emit.Lightweight",
        "System.Security.Permissions",
        "System.Security.AccessControl",
        "System.Security.Principal"
    };

    public SandboxedAssemblyLoadContext(string pluginPath, SecurityPolicy policy, RuntimeHookManager? hookManager = null)
        : base(isCollectible: true)
    {
        _policy = policy;
        _resolver = new AssemblyDependencyResolver(pluginPath);
        _hookManager = hookManager;
    }

    public Assembly LoadWithRewrite(string assemblyPath)
    {
        if (_hookManager != null)
        {
            var rewritten = _hookManager.RewriteAssembly(assemblyPath);
            using var stream = new MemoryStream(rewritten);
            return LoadFromStream(stream);
        }

        return LoadFromAssemblyPath(assemblyPath);
    }

    protected override Assembly? Load(AssemblyName assemblyName)
    {
        if (_policy.BlockedAssemblyPrefixes.Any(b => assemblyName.Name?.StartsWith(b) == true))
        {
            throw new SandboxException(ErrorCode.ForbiddenAssembly);
        }

        if (assemblyName.Name != null && BlockedSystemAssemblies.Contains(assemblyName.Name))
        {
            throw new SandboxException(ErrorCode.ForbiddenAssembly);
        }

        var resolved = _resolver.ResolveAssemblyToPath(assemblyName);
        if (resolved != null)
        {
            return LoadFromAssemblyPath(resolved);
        }

        try
        {
            return Default.LoadFromAssemblyName(assemblyName);
        }
        catch
        {
            return null;
        }
    }

    protected override IntPtr LoadUnmanagedDll(string unmanagedDllName)
    {
        return IntPtr.Zero;
    }

    public void UnloadPlugin()
    {
        Unload();
    }
}
