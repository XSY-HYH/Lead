namespace Lead;

public interface IHttpResponder
{
    Task<string> GetResponseAsync(string url, string method, string? body = null, Dictionary<string, string>? headers = null);
    void RecordRequest(string url, string method, string? body, Dictionary<string, string>? headers);
}
