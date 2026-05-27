namespace Lead;

public interface IHttpService
{
    Task<string> HttpGetAsync(string url, Dictionary<string, string>? headers = null, CancellationToken ct = default);
    Task<string> HttpPostAsync(string url, string body, string contentType = "application/json", CancellationToken ct = default);
}
