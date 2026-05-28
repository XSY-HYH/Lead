namespace Lead.Hooks.BuiltIn;

public class NetworkMethodHook : IMethodHook
{
    public string Category => "Network";

    public IEnumerable<MethodHookRule> GetRules()
    {
        var proxyType = typeof(Proxies.NetworkProxy);
        yield return new("System.Net.Http.HttpClient", "GetStringAsync", proxyType, "GetStringAsync", "Hook HttpClient.GetStringAsync");
    }
}
