using Lead;

public class SafePlugin : ISandboxedPlugin
{
    private IPluginContext _context = null!;

    public string Id => "safe-plugin-001";
    public string Name => "Safe Plugin";
    public string Version => "1.0.0";

    public void Initialize(IPluginContext context)
    {
        _context = context;
    }

    public async Task ExecuteAsync(CancellationToken cancellationToken)
    {
        var fileService = _context.GetService<IFileService>();
        if (fileService != null)
        {
            await fileService.WriteTextFileAsync("test.txt", "Hello from SafePlugin!", cancellationToken);
            var content = await fileService.ReadTextFileAsync("test.txt", cancellationToken);
            Console.WriteLine($"    [SafePlugin] Read back: {content}");
        }

        var httpService = _context.GetService<IHttpService>();
        Console.WriteLine($"    [SafePlugin] IHttpService available: {httpService != null}");

        _context.ReportProgress(50);
        _context.ReportProgress(100);

        await Task.CompletedTask;
    }

    public void Shutdown()
    {
    }
}
