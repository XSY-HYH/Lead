namespace Lead;

public class LoadResult
{
    public bool Success { get; init; }
    public string PluginId { get; init; } = string.Empty;
    public string? Error { get; init; }
    public ISandboxedPlugin? Plugin { get; init; }

    public static LoadResult Failed(string pluginId, string error)
    {
        return new LoadResult { Success = false, PluginId = pluginId, Error = error };
    }

    public static LoadResult Succeeded(string pluginId, ISandboxedPlugin plugin)
    {
        return new LoadResult { Success = true, PluginId = pluginId, Plugin = plugin };
    }
}
