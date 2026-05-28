using System.Reflection;
using Lead.Hooks;
using Lead.Hooks.Proxies;

namespace Lead;

public class PluginLoader : IDisposable
{
    private readonly SandboxConfiguration _config;
    private readonly AssemblyValidator _validator;
    private readonly RuntimeHookManager? _hookManager;
    private readonly Dictionary<string, SandboxedAssemblyLoadContext> _loadedContexts = new();
    private readonly Dictionary<string, ISandboxedPlugin> _pluginInstances = new();
    private readonly Dictionary<string, Assembly> _loadedAssemblies = new();

    public PluginLoader(SandboxConfiguration config)
    {
        _config = config;
        _validator = new AssemblyValidator(config.SecurityPolicy);

        if (config.EnableRuntimeHooks && config.HookDispatcher.GetAllRules().Count > 0)
        {
            _hookManager = new RuntimeHookManager(config.HookDispatcher);
            ConfigureProxies();
        }
    }

    public async Task<LoadResult> LoadPluginAsync(string dllPath, CancellationToken ct = default)
    {
        var pluginId = Guid.NewGuid().ToString("N");

        try
        {
            var validationResult = _validator.Validate(dllPath);

            if (!validationResult.IsValid && _config.StrictValidation)
            {
                var errors = string.Join(", ", validationResult.Errors.Select(e => e.Message));
                return LoadResult.Failed(pluginId, errors);
            }

            var loadContext = new SandboxedAssemblyLoadContext(dllPath, _config.SecurityPolicy, _hookManager);
            var assembly = loadContext.LoadWithRewrite(dllPath);

            _loadedContexts[pluginId] = loadContext;
            _loadedAssemblies[pluginId] = assembly;

            var pluginType = FindPluginType(assembly);
            if (pluginType != null)
            {
                var plugin = (ISandboxedPlugin)Activator.CreateInstance(pluginType)!;
                var context = CreatePluginContext(pluginId);
                plugin.Initialize(context);
                _pluginInstances[pluginId] = plugin;

                return LoadResult.Succeeded(pluginId, plugin, validationResult);
            }

            return LoadResult.RawAssembly(pluginId, validationResult);
        }
        catch (Exception ex)
        {
            return LoadResult.Failed(pluginId, $"{ErrorCode.PluginLoadFailed}: {ex.Message}");
        }
    }

    public async Task<ExecutionResult> ExecutePluginAsync(string pluginId, CancellationToken ct = default)
    {
        if (_pluginInstances.TryGetValue(pluginId, out var plugin))
        {
            try
            {
                await plugin.ExecuteAsync(ct);
                return ExecutionResult.Succeeded();
            }
            catch (SandboxException)
            {
                throw;
            }
            catch (OperationCanceledException)
            {
                return ExecutionResult.WasCancelled();
            }
            catch (Exception ex)
            {
                return ExecutionResult.Failed($"{ErrorCode.PluginLoadFailed}: {ex.Message}");
            }
        }

        return ExecutionResult.Failed(ErrorCode.PluginNotFound);
    }

    public async Task<object?> InvokeMethodAsync(string pluginId, string typeName, string methodName, object[]? args = null, CancellationToken ct = default)
    {
        if (!_loadedAssemblies.TryGetValue(pluginId, out var assembly))
            throw new SandboxException(ErrorCode.PluginNotFound);

        var type = assembly.GetType(typeName);
        if (type == null)
            throw new SandboxException(ErrorCode.PluginTypeNotFound);

        var method = type.GetMethod(methodName,
            BindingFlags.Public | BindingFlags.NonPublic | BindingFlags.Static | BindingFlags.Instance);

        if (method == null)
            throw new SandboxException(ErrorCode.ForbiddenMethod);

        object? instance = null;
        if (!method.IsStatic)
        {
            try { instance = Activator.CreateInstance(type); }
            catch { throw new SandboxException(ErrorCode.PluginLoadFailed); }
        }

        var task = method.Invoke(instance, args);
        if (task is Task t)
        {
            await t;
            var resultProperty = t.GetType().GetProperty("Result");
            return resultProperty?.GetValue(t);
        }

        return task;
    }

    public Assembly? GetLoadedAssembly(string pluginId)
    {
        return _loadedAssemblies.TryGetValue(pluginId, out var asm) ? asm : null;
    }

    public int GetHookRewriteCount() => _hookManager?.RewriteCount ?? 0;

    public void UnloadPlugin(string pluginId)
    {
        if (_pluginInstances.TryGetValue(pluginId, out var plugin))
        {
            try { plugin.Shutdown(); } catch { }
            _pluginInstances.Remove(pluginId);
        }

        _loadedAssemblies.Remove(pluginId);

        if (_loadedContexts.TryGetValue(pluginId, out var context))
        {
            context.UnloadPlugin();
            _loadedContexts.Remove(pluginId);
        }

        GC.Collect();
        GC.WaitForPendingFinalizers();
    }

    public void Dispose()
    {
        foreach (var pluginId in _loadedContexts.Keys.ToList())
            UnloadPlugin(pluginId);
    }

    private Type? FindPluginType(Assembly assembly)
    {
        var pluginInterface = typeof(ISandboxedPlugin);
        return assembly.GetTypes()
            .FirstOrDefault(t => t.IsClass && !t.IsAbstract && pluginInterface.IsAssignableFrom(t));
    }

    private PluginContext CreatePluginContext(string pluginId)
    {
        var context = new PluginContext(pluginId, _config);

        if (!context.HasService<IFileService>())
            context.InjectService<IFileService>(new SandboxFileService(pluginId, _config));

        if (!context.HasService<IHttpService>())
            context.InjectService<IHttpService>(new SandboxHttpService(_config));

        return context;
    }

    private void ConfigureProxies()
    {
        FileIOProxy.Mode = _config.FileRedirectMode;
        FileIOProxy.Redirector = _config.FileRedirector;
        FileIOProxy.SandboxRoot = _config.SandboxRootDirectory;

        NetworkProxy.Mode = _config.HttpRedirectMode;
        NetworkProxy.Responder = _config.HttpResponder;

        ProcessProxy.Mode = _config.FileRedirectMode;
        ReflectionProxy.Mode = _config.FileRedirectMode;
    }
}
