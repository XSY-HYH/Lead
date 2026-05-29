using Lead.Hooks;

namespace Lead.EnvironmentManagement.Hooks;

public class LinuxFileIOMethodHook : IMethodHook
{
    public string Category => "LinuxFileIO";

    public IEnumerable<MethodHookRule> GetRules()
    {
        var proxyType = typeof(Proxies.LinuxFileIOProxy);
        yield return new("System.IO.File", "Delete", proxyType, "Delete", "Hook File.Delete (Linux)");
        yield return new("System.IO.File", "ReadAllText", proxyType, "ReadAllText", "Hook File.ReadAllText (Linux)");
        yield return new("System.IO.File", "ReadAllBytes", proxyType, "ReadAllBytes", "Hook File.ReadAllBytes (Linux)");
        yield return new("System.IO.File", "WriteAllText", proxyType, "WriteAllText", "Hook File.WriteAllText (Linux)");
        yield return new("System.IO.File", "WriteAllBytes", proxyType, "WriteAllBytes", "Hook File.WriteAllBytes (Linux)");
        yield return new("System.IO.File", "Exists", proxyType, "Exists", "Hook File.Exists (Linux)");
        yield return new("System.IO.File", "ReadLines", proxyType, "ReadLines", "Hook File.ReadLines (Linux)");
        yield return new("System.IO.File", "AppendAllText", proxyType, "AppendAllText", "Hook File.AppendAllText (Linux)");
        yield return new("System.IO.Directory", "Exists", proxyType, "DirectoryExists", "Hook Directory.Exists (Linux)");
        yield return new("System.IO.Directory", "GetFiles", proxyType, "GetFiles", "Hook Directory.GetFiles (Linux)");
        yield return new("System.IO.Directory", "GetDirectories", proxyType, "GetDirectories", "Hook Directory.GetDirectories (Linux)");
        yield return new("System.IO.Directory", "CreateDirectory", proxyType, "CreateDirectory", "Hook Directory.CreateDirectory (Linux)");
    }
}
