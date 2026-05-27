using System.Reflection;
using System.Runtime.Loader;

namespace Lead;

public class SandboxedAssemblyLoadContext : AssemblyLoadContext
{
    private readonly SecurityPolicy _policy;

    public SandboxedAssemblyLoadContext(string pluginPath, SecurityPolicy policy)
        : base(isCollectible: true)
    {
        _policy = policy;
        _ = new AssemblyDependencyResolver(pluginPath);
    }

    protected override Assembly? Load(AssemblyName assemblyName)
    {
        if (_policy.BlockedAssemblyPrefixes.Any(b => assemblyName.Name?.StartsWith(b) == true))
        {
            throw new SandboxException(ErrorCode.ForbiddenAssembly);
        }

        return Default.LoadFromAssemblyName(assemblyName);
    }

    public void UnloadPlugin()
    {
        Unload();
    }
}
