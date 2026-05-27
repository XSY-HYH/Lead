namespace Lead;

public interface ISandboxedPlugin
{
    string Id { get; }
    string Name { get; }
    string Version { get; }

    void Initialize(IPluginContext context);
    Task ExecuteAsync(CancellationToken cancellationToken);
    void Shutdown();
}
