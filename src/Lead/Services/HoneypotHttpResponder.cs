using System.Text;

namespace Lead;

public class HoneypotHttpResponder : IHttpResponder
{
    private readonly Dictionary<string, Func<string, string>> _responders = new(StringComparer.OrdinalIgnoreCase);
    private readonly List<(DateTime Time, string Method, string Url, string? Body)> _requestLog = new();
    private readonly string _defaultJsonResponse;
    private readonly string _defaultHtmlResponse;
    private readonly string _defaultXmlResponse;

    public HoneypotHttpResponder()
    {
        _defaultJsonResponse = "{}";
        _defaultHtmlResponse = "<!DOCTYPE html><html><head><title>OK</title></head><body>OK</body></html>";
        _defaultXmlResponse = "<?xml version=\"1.0\" encoding=\"utf-8\"?><response><status>ok</status></response>";

        InitDefaultResponders();
    }

    public Task<string> GetResponseAsync(string url, string method, string? body = null, Dictionary<string, string>? headers = null)
    {
        RecordRequest(url, method, body, headers);

        if (_responders.TryGetValue(url, out var responder))
            return Task.FromResult(responder(method));

        if (url.Contains("/api/", StringComparison.OrdinalIgnoreCase) ||
            url.EndsWith(".json", StringComparison.OrdinalIgnoreCase))
            return Task.FromResult(_defaultJsonResponse);

        if (url.EndsWith(".xml", StringComparison.OrdinalIgnoreCase))
            return Task.FromResult(_defaultXmlResponse);

        return Task.FromResult(_defaultHtmlResponse);
    }

    public void RecordRequest(string url, string method, string? body, Dictionary<string, string>? headers)
    {
        _requestLog.Add((DateTime.UtcNow, method, url, body));
    }

    public IReadOnlyList<(DateTime Time, string Method, string Url, string? Body)> GetRequestLog() => _requestLog;

    public void AddResponder(string urlPattern, Func<string, string> responder)
    {
        _responders[urlPattern] = responder;
    }

    public void AddResponder(string urlPattern, string response)
    {
        _responders[urlPattern] = _ => response;
    }

    private void InitDefaultResponders()
    {
        _responders["http://169.254.169.254/latest/meta-data/"] = _ =>
            "ami-id: ami-0abcdef1234567890\ninstance-type: t2.micro\n";

        _responders["http://169.254.169.254/latest/meta-data/iam/security-credentials/"] = _ =>
            "{\"Code\":\"Success\",\"AccessKeyId\":\"ASIAFAKE123456789\",\"SecretAccessKey\":\"FAKE_SECRET_KEY_DO_NOT_USE\",\"Token\":\"FAKE_TOKEN\"}";

        _responders["http://localhost"] = _ => _defaultHtmlResponse;
        _responders["http://127.0.0.1"] = _ => _defaultHtmlResponse;

        _responders["https://api.example.com/"] = _ =>
            "{\"status\":\"ok\",\"version\":\"1.0\",\"sandboxed\":true}";
    }
}
