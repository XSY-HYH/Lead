using Lead.EnvironmentManagement.Hooks;
using Lead.EnvironmentManagement.Hooks.Proxies;
using Lead.Hooks;
using Lead.Hooks.BuiltIn;

namespace Lead.EnvironmentManagement;

public class PresetSandbox : IDisposable
{
    private PluginLoader? _loader;
    private readonly SandboxConfiguration _config;

    public SandboxConfiguration Configuration => _config;
    public RuntimeInspector? Inspector { get; private set; }

    private PresetSandbox(SandboxConfiguration config)
    {
        _config = config;
    }

    public static PresetSandbox CreateWindowsHoneypot(EnvironmentProfile? profile = null)
    {
        var config = new SandboxConfiguration
        {
            SandboxRootDirectory = "./sandbox_windows",
            FileRedirectMode = RedirectMode.Honeypot,
            HttpRedirectMode = RedirectMode.Honeypot,
            EnableRuntimeHooks = true,
            AllowAssemblyLoadFrom = true,
        };
        config.UseHoneypotDefaults();

        EnvironmentProxy.Profile = profile ?? EnvironmentProfile.WindowsDefault;

        config.HookDispatcher.Register(new EnvironmentMethodHook());

        return new PresetSandbox(config);
    }

    public static PresetSandbox CreateWindowsBlock(EnvironmentProfile? profile = null)
    {
        var config = new SandboxConfiguration
        {
            SandboxRootDirectory = "./sandbox_windows",
            FileRedirectMode = RedirectMode.Block,
            HttpRedirectMode = RedirectMode.Block,
            EnableRuntimeHooks = true,
            AllowAssemblyLoadFrom = false,
        };
        config.UseBlockDefaults();

        EnvironmentProxy.Profile = profile ?? EnvironmentProfile.WindowsDefault;

        config.HookDispatcher.Register(new EnvironmentMethodHook());

        return new PresetSandbox(config);
    }

    public static PresetSandbox CreateWindowsRedirect(EnvironmentProfile? profile = null)
    {
        var config = new SandboxConfiguration
        {
            SandboxRootDirectory = "./sandbox_windows",
            FileRedirectMode = RedirectMode.Redirect,
            HttpRedirectMode = RedirectMode.Redirect,
            EnableRuntimeHooks = true,
            AllowAssemblyLoadFrom = true,
        };
        config.UseRedirectDefaults();

        EnvironmentProxy.Profile = profile ?? EnvironmentProfile.WindowsDefault;

        config.HookDispatcher.Register(new EnvironmentMethodHook());

        return new PresetSandbox(config);
    }

    public static PresetSandbox CreateLinuxHoneypot(EnvironmentProfile? profile = null)
    {
        var config = new SandboxConfiguration
        {
            SandboxRootDirectory = "./sandbox_linux",
            FileRedirectMode = RedirectMode.Honeypot,
            HttpRedirectMode = RedirectMode.Honeypot,
            EnableRuntimeHooks = true,
            AllowAssemblyLoadFrom = true,
        };
        ConfigureLinuxDefaults(config, RedirectMode.Honeypot);

        var envProfile = profile ?? EnvironmentProfile.LinuxDefault;
        EnvironmentProxy.Profile = envProfile;

        config.HookDispatcher.Register(new IMethodHook[]
        {
            new LinuxFileIOMethodHook(),
            new NetworkMethodHook(),
            new ProcessMethodHook(),
            new ReflectionMethodHook(),
            new AssemblyLoadFromMethodHook(),
            new EnvironmentMethodHook(),
        });

        ConfigureLinuxProxies(config);

        return new PresetSandbox(config);
    }

    public static PresetSandbox CreateLinuxBlock(EnvironmentProfile? profile = null)
    {
        var config = new SandboxConfiguration
        {
            SandboxRootDirectory = "./sandbox_linux",
            FileRedirectMode = RedirectMode.Block,
            HttpRedirectMode = RedirectMode.Block,
            EnableRuntimeHooks = true,
            AllowAssemblyLoadFrom = false,
        };
        ConfigureLinuxDefaults(config, RedirectMode.Block);

        var envProfile = profile ?? EnvironmentProfile.LinuxDefault;
        EnvironmentProxy.Profile = envProfile;

        config.HookDispatcher.Register(new IMethodHook[]
        {
            new LinuxFileIOMethodHook(),
            new NetworkMethodHook(),
            new ProcessMethodHook(),
            new ReflectionMethodHook(),
            new AssemblyLoadFromMethodHook(),
            new EnvironmentMethodHook(),
        });

        ConfigureLinuxProxies(config);

        return new PresetSandbox(config);
    }

    public static PresetSandbox CreateLinuxRedirect(EnvironmentProfile? profile = null)
    {
        var config = new SandboxConfiguration
        {
            SandboxRootDirectory = "./sandbox_linux",
            FileRedirectMode = RedirectMode.Redirect,
            HttpRedirectMode = RedirectMode.Redirect,
            EnableRuntimeHooks = true,
            AllowAssemblyLoadFrom = true,
        };
        ConfigureLinuxDefaults(config, RedirectMode.Redirect);

        var envProfile = profile ?? EnvironmentProfile.LinuxDefault;
        EnvironmentProxy.Profile = envProfile;

        config.HookDispatcher.Register(new IMethodHook[]
        {
            new LinuxFileIOMethodHook(),
            new NetworkMethodHook(),
            new ProcessMethodHook(),
            new ReflectionMethodHook(),
            new AssemblyLoadFromMethodHook(),
            new EnvironmentMethodHook(),
        });

        ConfigureLinuxProxies(config);

        return new PresetSandbox(config);
    }

    public async Task<LoadResult> LoadPluginAsync(string dllPath, CancellationToken ct = default)
    {
        _loader ??= new PluginLoader(_config);
        var result = await _loader.LoadPluginAsync(dllPath, ct);

        if (result.Success)
        {
            var assembly = _loader.GetLoadedAssembly(result.PluginId);
            if (assembly != null)
            {
                Inspector = new RuntimeInspector(assembly, result.PluginId);
            }
        }

        return result;
    }

    public async Task<ExecutionResult> ExecutePluginAsync(string pluginId, CancellationToken ct = default)
    {
        if (_loader == null) throw new InvalidOperationException("No plugin loaded");
        return await _loader.ExecutePluginAsync(pluginId, ct);
    }

    public async Task<object?> InvokeMethodAsync(string pluginId, string typeName, string methodName, object[]? args = null, CancellationToken ct = default)
    {
        if (_loader == null) throw new InvalidOperationException("No plugin loaded");
        return await _loader.InvokeMethodAsync(pluginId, typeName, methodName, args, ct);
    }

    public void UnloadPlugin(string pluginId)
    {
        _loader?.UnloadPlugin(pluginId);
        Inspector = null;
    }

    public int GetHookRewriteCount() => _loader?.GetHookRewriteCount() ?? 0;

    private static void ConfigureLinuxProxies(SandboxConfiguration config)
    {
        LinuxFileIOProxy.Mode = config.FileRedirectMode;
        LinuxFileIOProxy.Redirector = config.FileRedirector;
        LinuxFileIOProxy.SandboxRoot = config.SandboxRootDirectory;
    }

    private static void ConfigureLinuxDefaults(SandboxConfiguration config, RedirectMode mode)
    {
        config.FileRedirectMode = mode;
        config.HttpRedirectMode = mode;
        config.EnableRuntimeHooks = true;

        if (mode == RedirectMode.Honeypot)
        {
            config.FileRedirector ??= new VirtualFileRedirector();
            config.HttpResponder ??= new HoneypotHttpResponder();
        }
        else if (mode == RedirectMode.Redirect)
        {
            config.FileRedirector ??= new VirtualFileRedirector();
            config.HttpResponder ??= new HoneypotHttpResponder();
        }
    }

    public void Dispose()
    {
        _loader?.Dispose();
    }
}
