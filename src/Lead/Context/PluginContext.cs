namespace Lead;

public class PluginContext : IPluginContext
{
    private readonly string _pluginId;
    private readonly SandboxConfiguration _config;
    private readonly Dictionary<Type, object> _services;
    private readonly CancellationTokenSource _cts;
    private DateTime _startTime;

    public event EventHandler<int>? ProgressReported;

    public PluginContext(string pluginId, SandboxConfiguration config)
    {
        _pluginId = pluginId;
        _config = config;
        _services = new Dictionary<Type, object>(config.Services);
        _cts = new CancellationTokenSource();
        _startTime = DateTime.UtcNow;
    }

    public T? GetService<T>() where T : class
    {
        return _services.TryGetValue(typeof(T), out var service) ? (T)service : null;
    }

    public bool HasService<T>() where T : class
    {
        return _services.ContainsKey(typeof(T));
    }

    public T GetConfigValue<T>(string key, T defaultValue = default!)
    {
        if (_config.PluginConfigs.TryGetValue(_pluginId, out var config) &&
            config.TryGetValue(key, out var value) &&
            value is T tValue)
            return tValue;

        return defaultValue;
    }

    public bool HasConfig(string key)
    {
        return _config.PluginConfigs.TryGetValue(_pluginId, out var config) &&
               config.ContainsKey(key);
    }

    public void CheckCancellation()
    {
        _cts.Token.ThrowIfCancellationRequested();
    }

    public void ReportProgress(int percentage)
    {
        if (percentage < 0 || percentage > 100)
            throw new SandboxException(ErrorCode.InvalidProgress);

        ProgressReported?.Invoke(this, percentage);
    }

    public void RequestMoreTime(TimeSpan additionalTime)
    {
        if (additionalTime > TimeSpan.FromMinutes(5))
            throw new SandboxException(ErrorCode.TimeRequestTooLong);

        _startTime = DateTime.UtcNow;
    }

    internal void InjectService<T>(T service) where T : class
    {
        _services[typeof(T)] = service;
    }

    internal void CheckExecutionTimeout()
    {
        if (DateTime.UtcNow - _startTime > TimeSpan.FromSeconds(_config.MaxExecutionSeconds))
            throw new SandboxException(ErrorCode.ExecutionTimeout);
    }
}
