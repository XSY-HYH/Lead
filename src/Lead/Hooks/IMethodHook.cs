namespace Lead.Hooks;

public interface IMethodHook
{
    string Category { get; }
    IEnumerable<MethodHookRule> GetRules();
}

public class MethodHookRule
{
    public string OriginalType { get; }
    public string OriginalMethod { get; }
    public Type ProxyType { get; }
    public string ProxyMethod { get; }
    public string? Description { get; }

    public MethodHookRule(string originalType, string originalMethod, Type proxyType, string proxyMethod, string? description = null)
    {
        OriginalType = originalType;
        OriginalMethod = originalMethod;
        ProxyType = proxyType;
        ProxyMethod = proxyMethod;
        Description = description;
    }
}
