namespace Lead.Hooks.BuiltIn;

public class ProcessMethodHook : IMethodHook
{
    public string Category => "Process";

    public IEnumerable<MethodHookRule> GetRules()
    {
        var proxyType = typeof(Proxies.ProcessProxy);
        yield return new("System.Diagnostics.Process", "Start", proxyType, "Start", "Hook Process.Start");
        yield return new("System.Diagnostics.Process", "Kill", proxyType, "Kill", "Hook Process.Kill");
    }
}
