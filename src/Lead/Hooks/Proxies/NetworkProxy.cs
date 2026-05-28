namespace Lead.Hooks.Proxies;

public static class NetworkProxy
{
    internal static RedirectMode Mode { get; set; } = RedirectMode.Honeypot;
    internal static IHttpResponder? Responder { get; set; }

    private static readonly List<string> RequestLog = new();

    public static async Task<string> GetStringAsync(object httpClient, string url)
    {
        RecordRequest("GET", url);
        switch (Mode)
        {
            case RedirectMode.Block:
                throw new SandboxException(ErrorCode.ForbiddenUrl);
            case RedirectMode.Honeypot:
                var response = Responder != null
                    ? await Responder.GetResponseAsync(url, "GET")
                    : "{}";
                return response;
            default:
                return "{}";
        }
    }

    private static void RecordRequest(string method, string url)
    {
        RequestLog.Add($"[{DateTime.Now:HH:mm:ss}] {method} -> {url}");
    }

    public static IReadOnlyList<string> GetRequestLog() => RequestLog.AsReadOnly();
}
