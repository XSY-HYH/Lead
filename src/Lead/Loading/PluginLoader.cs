using System.Reflection;

namespace Lead;

public class PluginLoader : IDisposable
{
    private readonly SandboxConfiguration _config;
    private readonly AssemblyValidator _validator;
    private readonly Dictionary<string, SandboxedAssemblyLoadContext> _loadedPlugins = new();
    private readonly Dictionary<string, ISandboxedPlugin> _pluginInstances = new();

    public PluginLoader(SandboxConfiguration config)
    {
        _config = config;
        _validator = new AssemblyValidator(config.SecurityPolicy);
    }

    public async Task<LoadResult> LoadPluginAsync(string dllPath, CancellationToken ct = default)
    {
        var pluginId = Guid.NewGuid().ToString("N");

        try
        {
            var validationResult = _validator.Validate(dllPath);

            if (!validationResult.IsValid)
            {
                var errors = string.Join(", ", validationResult.Errors.Select(e => e.Message));
                return LoadResult.Failed(pluginId, errors);
            }

            var loadContext = new SandboxedAssemblyLoadContext(dllPath, _config.SecurityPolicy);
            var assembly = loadContext.LoadFromAssemblyPath(dllPath);

            var pluginType = FindPluginType(assembly);
            if (pluginType == null)
            {
                loadContext.UnloadPlugin();
                return LoadResult.Failed(pluginId, ErrorCode.PluginTypeNotFound);
            }

            var plugin = (ISandboxedPlugin)Activator.CreateInstance(pluginType)!;

            var context = CreatePluginContext(pluginId);
            plugin.Initialize(context);

            _loadedPlugins[pluginId] = loadContext;
            _pluginInstances[pluginId] = plugin;

            return LoadResult.Succeeded(pluginId, plugin);
        }
        catch (Exception ex)
        {
            return LoadResult.Failed(pluginId, $"{ErrorCode.PluginLoadFailed}: {ex.Message}");
        }
    }

    public async Task<ExecutionResult> ExecutePluginAsync(string pluginId, CancellationToken ct = default)
    {
        if (!_pluginInstances.TryGetValue(pluginId, out var plugin))
            return ExecutionResult.Failed(ErrorCode.PluginNotFound);

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

    public void UnloadPlugin(string pluginId)
    {
        if (_pluginInstances.TryGetValue(pluginId, out var plugin))
        {
            try { plugin.Shutdown(); } catch { }
            _pluginInstances.Remove(pluginId);
        }

        if (_loadedPlugins.TryGetValue(pluginId, out var context))
        {
            context.UnloadPlugin();
            _loadedPlugins.Remove(pluginId);
        }

        GC.Collect();
        GC.WaitForPendingFinalizers();
    }

    public void Dispose()
    {
        foreach (var pluginId in _loadedPlugins.Keys.ToList())
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
}
