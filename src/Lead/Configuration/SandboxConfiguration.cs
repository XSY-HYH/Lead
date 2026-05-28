using Lead.Hooks;
using Lead.Hooks.BuiltIn;

namespace Lead;

public class SandboxConfiguration
{
    public string SandboxRootDirectory { get; set; } = "./sandbox_data";
    public bool ReadOnlyMode { get; set; } = false;

    public int MaxExecutionSeconds { get; set; } = 30;
    public int MaxFileSize { get; set; } = 10 * 1024 * 1024;
    public long MaxBytesRead { get; set; } = 100 * 1024 * 1024;
    public long MaxBytesWritten { get; set; } = 50 * 1024 * 1024;
    public int MaxHttpRequests { get; set; } = 100;
    public int HttpTimeoutSeconds { get; set; } = 10;

    public HashSet<string> AllowedFileExtensions { get; set; } = new() { ".txt", ".json", ".xml", ".csv", ".log", ".dat" };
    public HashSet<string> AllowedUrlPatterns { get; set; } = new();
    public HashSet<string> AllowedDirectories { get; set; } = new();

    public RedirectMode FileRedirectMode { get; set; } = RedirectMode.Honeypot;
    public IFileRedirector? FileRedirector { get; set; }

    public RedirectMode HttpRedirectMode { get; set; } = RedirectMode.Honeypot;
    public IHttpResponder? HttpResponder { get; set; }
    public Dictionary<string, string>? HttpRedirectTargets { get; set; }

    public SecurityPolicy SecurityPolicy { get; set; } = new();

    public bool StrictValidation { get; set; } = false;

    public bool EnableRuntimeHooks { get; set; } = true;

    public bool AllowAssemblyLoadFrom { get; set; } = true;

    public MethodHookDispatcher HookDispatcher { get; } = new();

    public Dictionary<string, Dictionary<string, object>> PluginConfigs { get; set; } = new();

    private readonly Dictionary<Type, object> _services = new();

    public SandboxConfiguration RegisterService<T>(T service) where T : class
    {
        _services[typeof(T)] = service;
        return this;
    }

    internal IReadOnlyDictionary<Type, object> Services => _services;

    public SandboxConfiguration UseHoneypotDefaults()
    {
        FileRedirectMode = RedirectMode.Honeypot;
        FileRedirector ??= new VirtualFileRedirector();

        HttpRedirectMode = RedirectMode.Honeypot;
        HttpResponder ??= new HoneypotHttpResponder();

        EnableRuntimeHooks = true;
        RegisterDefaultHooks();

        return this;
    }

    public SandboxConfiguration UseRedirectDefaults()
    {
        FileRedirectMode = RedirectMode.Redirect;
        FileRedirector ??= new VirtualFileRedirector();

        HttpRedirectMode = RedirectMode.Redirect;
        HttpResponder ??= new HoneypotHttpResponder();

        EnableRuntimeHooks = true;
        RegisterDefaultHooks();

        return this;
    }

    public SandboxConfiguration UseBlockDefaults()
    {
        FileRedirectMode = RedirectMode.Block;
        HttpRedirectMode = RedirectMode.Block;

        EnableRuntimeHooks = true;
        RegisterDefaultHooks();

        return this;
    }

    private void RegisterDefaultHooks()
    {
        HookDispatcher.Register(new IMethodHook[]
        {
            new FileIOMethodHook(),
            new NetworkMethodHook(),
            new ProcessMethodHook(),
            new ReflectionMethodHook(),
            new AssemblyLoadFromMethodHook()
        });
    }
}
