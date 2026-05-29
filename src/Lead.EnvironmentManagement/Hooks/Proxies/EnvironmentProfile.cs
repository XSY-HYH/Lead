namespace Lead.EnvironmentManagement.Hooks.Proxies;

public class EnvironmentProfile
{
    public bool IsLinux { get; init; }
    public string MachineName { get; init; } = "DESKTOP-SANDBOX";
    public string UserName { get; init; } = "sandbox_user";
    public OperatingSystem OSVersion { get; init; } = new(PlatformID.Win32NT, new Version(10, 0, 19045, 0));
    public int ProcessorCount { get; init; } = 8;
    public bool Is64BitOperatingSystem { get; init; } = true;
    public bool Is64BitProcess { get; init; } = true;
    public string SystemDirectory { get; init; } = @"C:\Windows\System32";
    public string FrameworkDescription { get; init; } = ".NET 8.0.0";
    public string OSDescriptionString { get; init; } = "Microsoft Windows 10.0.19045";
    public Architecture ProcessArchitecture { get; init; } = Architecture.X64;
    public Architecture OSArchitecture { get; init; } = Architecture.X64;
    public Dictionary<Environment.SpecialFolder, string> FolderPaths { get; init; } = new();
    public Dictionary<string, string> EnvironmentVariables { get; init; } = new();

    public static EnvironmentProfile WindowsDefault => new()
    {
        IsLinux = false,
        MachineName = "DESKTOP-SANDBOX",
        UserName = "sandbox_user",
        OSVersion = new(PlatformID.Win32NT, new Version(10, 0, 19045, 0)),
        ProcessorCount = 8,
        Is64BitOperatingSystem = true,
        Is64BitProcess = true,
        SystemDirectory = @"C:\Windows\System32",
        FrameworkDescription = ".NET 8.0.0",
        OSDescriptionString = "Microsoft Windows 10.0.19045",
        ProcessArchitecture = Architecture.X64,
        OSArchitecture = Architecture.X64,
        FolderPaths = new()
        {
            { Environment.SpecialFolder.Desktop, @"C:\Users\sandbox_user\Desktop" },
            { Environment.SpecialFolder.MyDocuments, @"C:\Users\sandbox_user\Documents" },
            { Environment.SpecialFolder.ProgramFiles, @"C:\Program Files" },
            { Environment.SpecialFolder.ProgramFilesX86, @"C:\Program Files (x86)" },
            { Environment.SpecialFolder.Windows, @"C:\Windows" },
            { Environment.SpecialFolder.System, @"C:\Windows\System32" },
            { Environment.SpecialFolder.ApplicationData, @"C:\Users\sandbox_user\AppData\Roaming" },
            { Environment.SpecialFolder.LocalApplicationData, @"C:\Users\sandbox_user\AppData\Local" },
            { Environment.SpecialFolder.UserProfile, @"C:\Users\sandbox_user" },
        },
        EnvironmentVariables = new()
        {
            { "OS", "Windows_NT" },
            { "COMPUTERNAME", "DESKTOP-SANDBOX" },
            { "USERNAME", "sandbox_user" },
            { "USERPROFILE", @"C:\Users\sandbox_user" },
            { "HOMEDRIVE", "C:" },
            { "HOMEPATH", @"\Users\sandbox_user" },
            { "SYSTEMROOT", @"C:\Windows" },
            { "WINDIR", @"C:\Windows" },
            { "TEMP", @"C:\Users\sandbox_user\AppData\Local\Temp" },
            { "TMP", @"C:\Users\sandbox_user\AppData\Local\Temp" },
            { "PATH", @"C:\Windows\System32;C:\Windows;C:\Users\sandbox_user\AppData\Local" },
            { "PROCESSOR_ARCHITECTURE", "AMD64" },
            { "NUMBER_OF_PROCESSORS", "8" },
        }
    };

    public static EnvironmentProfile LinuxDefault => new()
    {
        IsLinux = true,
        MachineName = "sandbox-host",
        UserName = "sandbox_user",
        OSVersion = new(PlatformID.Unix, new Version(6, 5, 0, 44)),
        ProcessorCount = 4,
        Is64BitOperatingSystem = true,
        Is64BitProcess = true,
        SystemDirectory = "/usr/bin",
        FrameworkDescription = ".NET 8.0.0",
        OSDescriptionString = "Linux 6.5.0-44-generic #44~22.04.1-Ubuntu SMP x86_64",
        ProcessArchitecture = Architecture.X64,
        OSArchitecture = Architecture.X64,
        FolderPaths = new()
        {
            { Environment.SpecialFolder.Desktop, "/home/sandbox_user/Desktop" },
            { Environment.SpecialFolder.MyDocuments, "/home/sandbox_user/Documents" },
            { Environment.SpecialFolder.ProgramFiles, "/usr/bin" },
            { Environment.SpecialFolder.Windows, "/usr" },
            { Environment.SpecialFolder.System, "/usr/bin" },
            { Environment.SpecialFolder.ApplicationData, "/home/sandbox_user/.config" },
            { Environment.SpecialFolder.LocalApplicationData, "/home/sandbox_user/.local/share" },
            { Environment.SpecialFolder.UserProfile, "/home/sandbox_user" },
        },
        EnvironmentVariables = new()
        {
            { "HOME", "/home/sandbox_user" },
            { "USER", "sandbox_user" },
            { "HOSTNAME", "sandbox-host" },
            { "SHELL", "/bin/bash" },
            { "PATH", "/usr/local/bin:/usr/bin:/bin:/usr/local/sbin:/usr/sbin:/sbin" },
            { "LANG", "en_US.UTF-8" },
            { "TERM", "xterm-256color" },
            { "PWD", "/home/sandbox_user" },
            { "LOGNAME", "sandbox_user" },
            { "XDG_CONFIG_HOME", "/home/sandbox_user/.config" },
            { "XDG_DATA_HOME", "/home/sandbox_user/.local/share" },
            { "DOTNET_ROOT", "/usr/share/dotnet" },
        }
    };

    public static EnvironmentProfile LinuxArm64 => new()
    {
        IsLinux = true,
        MachineName = "sandbox-arm64",
        UserName = "sandbox_user",
        OSVersion = new(PlatformID.Unix, new Version(6, 1, 0, 21)),
        ProcessorCount = 4,
        Is64BitOperatingSystem = true,
        Is64BitProcess = true,
        SystemDirectory = "/usr/bin",
        FrameworkDescription = ".NET 8.0.0",
        OSDescriptionString = "Linux 6.1.0-21-cloud-arm64 #1 SMP Debian aarch64",
        ProcessArchitecture = Architecture.Arm64,
        OSArchitecture = Architecture.Arm64,
        FolderPaths = new()
        {
            { Environment.SpecialFolder.Desktop, "/home/sandbox_user/Desktop" },
            { Environment.SpecialFolder.MyDocuments, "/home/sandbox_user/Documents" },
            { Environment.SpecialFolder.ProgramFiles, "/usr/bin" },
            { Environment.SpecialFolder.Windows, "/usr" },
            { Environment.SpecialFolder.System, "/usr/bin" },
            { Environment.SpecialFolder.ApplicationData, "/home/sandbox_user/.config" },
            { Environment.SpecialFolder.LocalApplicationData, "/home/sandbox_user/.local/share" },
            { Environment.SpecialFolder.UserProfile, "/home/sandbox_user" },
        },
        EnvironmentVariables = new()
        {
            { "HOME", "/home/sandbox_user" },
            { "USER", "sandbox_user" },
            { "HOSTNAME", "sandbox-arm64" },
            { "SHELL", "/bin/bash" },
            { "PATH", "/usr/local/bin:/usr/bin:/bin:/usr/local/sbin:/usr/sbin:/sbin" },
            { "LANG", "en_US.UTF-8" },
            { "TERM", "xterm-256color" },
            { "PWD", "/home/sandbox_user" },
            { "LOGNAME", "sandbox_user" },
            { "DOTNET_ROOT", "/usr/share/dotnet" },
        }
    };
}
