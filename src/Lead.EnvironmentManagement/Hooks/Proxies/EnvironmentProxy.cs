using System.Collections;

namespace Lead.EnvironmentManagement.Hooks.Proxies;

public static class EnvironmentProxy
{
    internal static EnvironmentProfile Profile { get; set; } = EnvironmentProfile.WindowsDefault;

    public static string GetFolderPath(int folder)
    {
        var specialFolder = (Environment.SpecialFolder)folder;
        if (Profile.FolderPaths.TryGetValue(specialFolder, out var path))
            return path;
        return Profile.IsLinux ? $"/usr/share/{specialFolder.ToString().ToLower()}" : $"C:\\Users\\{Profile.UserName}\\{specialFolder}";
    }

    public static string? GetEnvironmentVariable(string variable)
    {
        if (Profile.EnvironmentVariables.TryGetValue(variable, out var value))
            return value;
        return null;
    }

    public static IDictionary GetEnvironmentVariables()
    {
        return new Hashtable(Profile.EnvironmentVariables);
    }

    public static string GetMachineName() => Profile.MachineName;

    public static string GetUserName() => Profile.UserName;

    public static OperatingSystem GetOSVersion() => Profile.OSVersion;

    public static int GetProcessorCount() => Profile.ProcessorCount;

    public static bool GetIs64BitOperatingSystem() => Profile.Is64BitOperatingSystem;

    public static bool GetIs64BitProcess() => Profile.Is64BitProcess;

    public static string GetSystemDirectory() => Profile.SystemDirectory;

    public static string GetFrameworkDescription() => Profile.FrameworkDescription;

    public static string GetOSDescription() => Profile.OSDescriptionString;

    public static Architecture GetProcessArchitecture() => Profile.ProcessArchitecture;

    public static Architecture GetOSArchitecture() => Profile.OSArchitecture;
}

public enum Architecture
{
    X86 = 0,
    X64 = 1,
    Arm = 2,
    Arm64 = 3,
    Wasm = 4,
    S390x = 5,
    LoongArch64 = 6,
    Armv6 = 7,
    Ppc64le = 8
}
