namespace Lead.Hooks.BuiltIn;

public class FileIOMethodHook : IMethodHook
{
    public string Category => "FileIO";

    public IEnumerable<MethodHookRule> GetRules()
    {
        var proxyType = typeof(Proxies.FileIOProxy);
        yield return new("System.IO.File", "Delete", proxyType, "Delete", "Hook File.Delete");
        yield return new("System.IO.File", "ReadAllText", proxyType, "ReadAllText", "Hook File.ReadAllText");
        yield return new("System.IO.File", "ReadAllBytes", proxyType, "ReadAllBytes", "Hook File.ReadAllBytes");
        yield return new("System.IO.File", "WriteAllText", proxyType, "WriteAllText", "Hook File.WriteAllText");
        yield return new("System.IO.File", "WriteAllBytes", proxyType, "WriteAllBytes", "Hook File.WriteAllBytes");
        yield return new("System.IO.File", "Exists", proxyType, "Exists", "Hook File.Exists");
        yield return new("System.IO.File", "ReadLines", proxyType, "ReadLines", "Hook File.ReadLines");
        yield return new("System.IO.File", "AppendAllText", proxyType, "AppendAllText", "Hook File.AppendAllText");
    }
}
