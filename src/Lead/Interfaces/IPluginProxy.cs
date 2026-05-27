namespace Lead;

public interface IPluginProxy
{
    Task<TResult> CallAsync<TResult>(string methodName, object[]? args);
}
