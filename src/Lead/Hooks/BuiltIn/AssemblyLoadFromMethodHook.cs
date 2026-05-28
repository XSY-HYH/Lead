namespace Lead.Hooks.BuiltIn;

public class AssemblyLoadFromMethodHook : IMethodHook
{
    public string Category => "AssemblyLoading";

    public IEnumerable<MethodHookRule> GetRules()
    {
        var proxyType = typeof(Proxies.AssemblyLoadFromProxy);
        yield return new("System.Reflection.Assembly", "LoadFrom", proxyType, "LoadFrom", "Hook Assembly.LoadFrom -> sandbox ALC");
        yield return new("System.Reflection.Assembly", "Load", proxyType, "Load", "Hook Assembly.Load -> sandbox ALC");
    }
}
