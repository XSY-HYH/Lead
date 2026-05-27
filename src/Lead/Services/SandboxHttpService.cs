using System.Net;
using System.Text.RegularExpressions;

namespace Lead;

public class SandboxHttpService : IHttpService
{
    private readonly SandboxConfiguration _config;
    private readonly RedirectMode _httpRedirectMode;
    private readonly IHttpResponder? _responder;
    private int _requestCount;

    public SandboxHttpService(SandboxConfiguration config)
    {
        _config = config;
        _httpRedirectMode = config.HttpRedirectMode;
        _responder = config.HttpResponder;
    }

    public async Task<string> HttpGetAsync(string url, Dictionary<string, string>? headers = null, CancellationToken ct = default)
    {
        CheckResourceLimits();

        var validation = ValidateUrl(url);
        if (!validation.IsValid)
        {
            if (_httpRedirectMode == RedirectMode.Block)
                throw new SandboxException(validation.ErrorCode!);

            if (_httpRedirectMode == RedirectMode.Honeypot)
                return await _responder!.GetResponseAsync(url, "GET", null, headers);

            return await ExecuteRedirectedGetAsync(url, headers, ct);
        }

        return await ExecuteRealGetAsync(url, headers, ct);
    }

    public async Task<string> HttpPostAsync(string url, string body, string contentType = "application/json", CancellationToken ct = default)
    {
        CheckResourceLimits();

        var validation = ValidateUrl(url);
        if (!validation.IsValid)
        {
            if (_httpRedirectMode == RedirectMode.Block)
                throw new SandboxException(validation.ErrorCode!);

            if (_httpRedirectMode == RedirectMode.Honeypot)
                return await _responder!.GetResponseAsync(url, "POST", body);

            return await ExecuteRedirectedPostAsync(url, body, contentType, ct);
        }

        return await ExecuteRealPostAsync(url, body, contentType, ct);
    }

    private async Task<string> ExecuteRealGetAsync(string url, Dictionary<string, string>? headers, CancellationToken ct)
    {
        using var client = CreateHttpClient();
        var request = new HttpRequestMessage(HttpMethod.Get, url);
        if (headers != null)
        {
            foreach (var kv in headers)
                request.Headers.TryAddWithoutValidation(kv.Key, kv.Value);
        }

        var response = await client.SendAsync(request, ct);
        var content = await response.Content.ReadAsStringAsync(ct);
        Interlocked.Increment(ref _requestCount);

        if (!response.IsSuccessStatusCode)
            throw new SandboxException(ErrorCode.HttpFailed);

        return content;
    }

    private async Task<string> ExecuteRealPostAsync(string url, string body, string contentType, CancellationToken ct)
    {
        using var client = CreateHttpClient();
        var httpContent = new StringContent(body, System.Text.Encoding.UTF8, contentType);

        var response = await client.PostAsync(url, httpContent, ct);
        var responseContent = await response.Content.ReadAsStringAsync(ct);
        Interlocked.Increment(ref _requestCount);

        if (!response.IsSuccessStatusCode)
            throw new SandboxException(ErrorCode.HttpFailed);

        return responseContent;
    }

    private async Task<string> ExecuteRedirectedGetAsync(string url, Dictionary<string, string>? headers, CancellationToken ct)
    {
        var redirectUrl = FindRedirectUrl(url);
        if (redirectUrl != null)
            return await ExecuteRealGetAsync(redirectUrl, headers, ct);

        if (_responder != null)
            return await _responder.GetResponseAsync(url, "GET", null, headers);

        throw new SandboxException(ErrorCode.ForbiddenUrl);
    }

    private async Task<string> ExecuteRedirectedPostAsync(string url, string body, string contentType, CancellationToken ct)
    {
        var redirectUrl = FindRedirectUrl(url);
        if (redirectUrl != null)
            return await ExecuteRealPostAsync(redirectUrl, body, contentType, ct);

        if (_responder != null)
            return await _responder.GetResponseAsync(url, "POST", body);

        throw new SandboxException(ErrorCode.ForbiddenUrl);
    }

    private string? FindRedirectUrl(string url)
    {
        if (_config.HttpRedirectTargets == null)
            return null;

        foreach (var mapping in _config.HttpRedirectTargets)
        {
            if (Regex.IsMatch(url, mapping.Key, RegexOptions.IgnoreCase))
                return mapping.Value;
        }

        return null;
    }

    private (bool IsValid, string? ErrorCode) ValidateUrl(string url)
    {
        if (!Uri.TryCreate(url, UriKind.Absolute, out var uri))
            return (false, ErrorCode.InvalidUrl);

        if (uri.Scheme != "http" && uri.Scheme != "https")
            return (false, ErrorCode.ForbiddenProtocol);

        var allowed = _config.AllowedUrlPatterns.Any(pattern =>
            Regex.IsMatch(url, pattern, RegexOptions.IgnoreCase));

        if (!allowed)
            return (false, ErrorCode.ForbiddenUrl);

        if (IsPrivateIp(uri.Host))
            return (false, ErrorCode.PrivateIp);

        return (true, null);
    }

    private static bool IsPrivateIp(string host)
    {
        if (host == "localhost" || host == "127.0.0.1" || host == "::1")
            return true;

        if (IPAddress.TryParse(host, out var ip))
        {
            byte[] bytes = ip.GetAddressBytes();
            if (ip.AddressFamily == System.Net.Sockets.AddressFamily.InterNetwork)
            {
                if (bytes[0] == 10) return true;
                if (bytes[0] == 172 && bytes[1] >= 16 && bytes[1] <= 31) return true;
                if (bytes[0] == 192 && bytes[1] == 168) return true;
            }
        }

        return false;
    }

    private HttpClient CreateHttpClient()
    {
        var handler = new HttpClientHandler
        {
            AllowAutoRedirect = false,
            AutomaticDecompression = System.Net.DecompressionMethods.None,
            UseProxy = false,
            UseCookies = false
        };

        var client = new HttpClient(handler);
        client.Timeout = TimeSpan.FromSeconds(_config.HttpTimeoutSeconds);
        client.DefaultRequestHeaders.Add("User-Agent", "SandboxedPlugin/1.0");

        return client;
    }

    private void CheckResourceLimits()
    {
        if (_requestCount >= _config.MaxHttpRequests)
            throw new SandboxException(ErrorCode.HttpLimitExceeded);
    }
}
