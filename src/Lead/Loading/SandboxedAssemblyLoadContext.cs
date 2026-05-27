using System.Reflection;
using System.Runtime.Loader;

namespace Lead;

public class SandboxedAssemblyLoadContext : AssemblyLoadContext
{
    private readonly SecurityPolicy _policy;
    private readonly AssemblyDependencyResolver _resolver;

    private static readonly HashSet<string> BlockedSystemAssemblies = new(StringComparer.OrdinalIgnoreCase)
    {
        "Microsoft.Win32.Registry",
        "System.Diagnostics.Process",
        "System.Diagnostics.EventLog",
        "System.Net.Sockets",
        "System.Runtime.InteropServices.RuntimeInformation"
    };

    public SandboxedAssemblyLoadContext(string pluginPath, SecurityPolicy policy)
        : base(isCollectible: true)
    {
        _policy = policy;
        _resolver = new AssemblyDependencyResolver(pluginPath);
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

        return Default.LoadFromAssemblyName(assemblyName);
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
