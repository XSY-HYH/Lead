namespace Lead;

public interface IPluginContext
{
    T? GetService<T>() where T : class;
    bool HasService<T>() where T : class;

    T GetConfigValue<T>(string key, T defaultValue = default!);
    bool HasConfig(string key);

    void CheckCancellation();
    void ReportProgress(int percentage);
    void RequestMoreTime(TimeSpan additionalTime);

    event EventHandler<int> ProgressReported;
}
