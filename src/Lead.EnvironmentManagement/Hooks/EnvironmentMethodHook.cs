using Lead.Hooks;

namespace Lead.EnvironmentManagement.Hooks;

public class EnvironmentMethodHook : IMethodHook
{
    public string Category => "EnvironmentInfo";

    public IEnumerable<MethodHookRule> GetRules()
    {
        var proxyType = typeof(Proxies.EnvironmentProxy);
        yield return new("System.Environment", "GetFolderPath", proxyType, "GetFolderPath", "Hook Environment.GetFolderPath");
        yield return new("System.Environment", "GetEnvironmentVariable", proxyType, "GetEnvironmentVariable", "Hook Environment.GetEnvironmentVariable");
        yield return new("System.Environment", "GetEnvironmentVariables", proxyType, "GetEnvironmentVariables", "Hook Environment.GetEnvironmentVariables");
        yield return new("System.Environment", "get_MachineName", proxyType, "GetMachineName", "Hook Environment.MachineName");
        yield return new("System.Environment", "get_UserName", proxyType, "GetUserName", "Hook Environment.UserName");
        yield return new("System.Environment", "get_OSVersion", proxyType, "GetOSVersion", "Hook Environment.OSVersion");
        yield return new("System.Environment", "get_ProcessorCount", proxyType, "GetProcessorCount", "Hook Environment.ProcessorCount");
        yield return new("System.Environment", "get_Is64BitOperatingSystem", proxyType, "GetIs64BitOperatingSystem", "Hook Environment.Is64BitOperatingSystem");
        yield return new("System.Environment", "get_Is64BitProcess", proxyType, "GetIs64BitProcess", "Hook Environment.Is64BitProcess");
        yield return new("System.Environment", "get_SystemDirectory", proxyType, "GetSystemDirectory", "Hook Environment.SystemDirectory");
        yield return new("System.Runtime.InteropServices.RuntimeInformation", "get_FrameworkDescription", proxyType, "GetFrameworkDescription", "Hook RuntimeInformation.FrameworkDescription");
        yield return new("System.Runtime.InteropServices.RuntimeInformation", "get_OSDescription", proxyType, "GetOSDescription", "Hook RuntimeInformation.OSDescription");
        yield return new("System.Runtime.InteropServices.RuntimeInformation", "get_ProcessArchitecture", proxyType, "GetProcessArchitecture", "Hook RuntimeInformation.ProcessArchitecture");
        yield return new("System.Runtime.InteropServices.RuntimeInformation", "get_OSArchitecture", proxyType, "GetOSArchitecture", "Hook RuntimeInformation.OSArchitecture");
    }
}
