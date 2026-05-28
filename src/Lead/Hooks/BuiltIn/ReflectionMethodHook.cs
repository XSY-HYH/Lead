namespace Lead.Hooks.BuiltIn;

public class ReflectionMethodHook : IMethodHook
{
    public string Category => "Reflection";

    public IEnumerable<MethodHookRule> GetRules()
    {
        var proxyType = typeof(Proxies.ReflectionProxy);
        yield return new("System.Reflection.MethodInfo", "Invoke", proxyType, "Invoke", "Hook MethodInfo.Invoke");
        yield return new("System.Activator", "CreateInstance", proxyType, "CreateInstance", "Hook Activator.CreateInstance");
    }
}
