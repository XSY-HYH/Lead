using System.Collections.Concurrent;

namespace Lead.EnvironmentManagement.Hooks.Proxies;

public static class LinuxFileIOProxy
{
    internal static RedirectMode Mode { get; set; } = RedirectMode.Honeypot;
    internal static IFileRedirector? Redirector { get; set; }
    internal static string SandboxRoot { get; set; } = "./sandbox_data";

    private static readonly ConcurrentDictionary<string, string> _virtualFiles = new(StringComparer.OrdinalIgnoreCase);
    private static readonly ConcurrentDictionary<string, byte[]> _virtualBinaryFiles = new(StringComparer.OrdinalIgnoreCase);
    private static readonly ConcurrentDictionary<string, bool> _virtualDirectories = new(StringComparer.OrdinalIgnoreCase);
    private static readonly List<string> _accessLog = new();

    static LinuxFileIOProxy()
    {
        InitLinuxVirtualFS();
    }

    public static void Delete(string path)
    {
        RecordAccess("DELETE", path);
        switch (Mode)
        {
            case RedirectMode.Block:
                throw new SandboxException(ErrorCode.PathTraversal);
            case RedirectMode.Redirect:
                var redirectPath = Redirector?.RedirectPath(path);
                if (redirectPath != null)
                {
                    var full = Path.GetFullPath(Path.Combine(SandboxRoot, redirectPath));
                    if (File.Exists(full)) File.Delete(full);
                }
                break;
            case RedirectMode.Honeypot:
                _virtualFiles.TryRemove(NormalizePath(path), out _);
                _virtualBinaryFiles.TryRemove(NormalizePath(path), out _);
                break;
        }
    }

    public static string ReadAllText(string path)
    {
        RecordAccess("READ_ALL_TEXT", path);
        switch (Mode)
        {
            case RedirectMode.Block:
                throw new SandboxException(ErrorCode.PathTraversal);
            case RedirectMode.Redirect:
                var redirectPath = Redirector?.RedirectPath(path);
                if (redirectPath != null)
                {
                    var full = Path.GetFullPath(Path.Combine(SandboxRoot, redirectPath));
                    return File.Exists(full) ? File.ReadAllText(full) : "";
                }
                return "";
            case RedirectMode.Honeypot:
                var normalized = NormalizePath(path);
                if (_virtualFiles.TryGetValue(normalized, out var content))
                    return content;
                var virtualContent = Redirector?.GetVirtualContent(path);
                return virtualContent ?? "";
            default:
                return "";
        }
    }

    public static byte[] ReadAllBytes(string path)
    {
        RecordAccess("READ_ALL_BYTES", path);
        switch (Mode)
        {
            case RedirectMode.Block:
                throw new SandboxException(ErrorCode.PathTraversal);
            case RedirectMode.Redirect:
                var redirectPath = Redirector?.RedirectPath(path);
                if (redirectPath != null)
                {
                    var full = Path.GetFullPath(Path.Combine(SandboxRoot, redirectPath));
                    return File.Exists(full) ? File.ReadAllBytes(full) : Array.Empty<byte>();
                }
                return Array.Empty<byte>();
            case RedirectMode.Honeypot:
                var normalized = NormalizePath(path);
                if (_virtualBinaryFiles.TryGetValue(normalized, out var data))
                    return data;
                var virtualContent = Redirector?.GetVirtualBinaryContent(path);
                return virtualContent ?? Array.Empty<byte>();
            default:
                return Array.Empty<byte>();
        }
    }

    public static void WriteAllText(string path, string contents)
    {
        RecordAccess("WRITE_ALL_TEXT", path);
        switch (Mode)
        {
            case RedirectMode.Block:
                throw new SandboxException(ErrorCode.PathTraversal);
            case RedirectMode.Redirect:
                var redirectPath = Redirector?.RedirectPath(path);
                if (redirectPath != null)
                {
                    var full = Path.GetFullPath(Path.Combine(SandboxRoot, redirectPath));
                    Directory.CreateDirectory(Path.GetDirectoryName(full)!);
                    File.WriteAllText(full, contents);
                }
                break;
            case RedirectMode.Honeypot:
                _virtualFiles[NormalizePath(path)] = contents;
                Redirector?.RecordWrite(path, contents);
                break;
        }
    }

    public static void WriteAllBytes(string path, byte[] bytes)
    {
        RecordAccess("WRITE_ALL_BYTES", path);
        switch (Mode)
        {
            case RedirectMode.Block:
                throw new SandboxException(ErrorCode.PathTraversal);
            case RedirectMode.Redirect:
                var redirectPath = Redirector?.RedirectPath(path);
                if (redirectPath != null)
                {
                    var full = Path.GetFullPath(Path.Combine(SandboxRoot, redirectPath));
                    Directory.CreateDirectory(Path.GetDirectoryName(full)!);
                    File.WriteAllBytes(full, bytes);
                }
                break;
            case RedirectMode.Honeypot:
                _virtualBinaryFiles[NormalizePath(path)] = bytes;
                Redirector?.RecordWrite(path, bytes);
                break;
        }
    }

    public static bool Exists(string path)
    {
        RecordAccess("EXISTS", path);
        switch (Mode)
        {
            case RedirectMode.Block:
                throw new SandboxException(ErrorCode.PathTraversal);
            case RedirectMode.Redirect:
                var redirectPath = Redirector?.RedirectPath(path);
                if (redirectPath != null)
                {
                    var full = Path.GetFullPath(Path.Combine(SandboxRoot, redirectPath));
                    return File.Exists(full);
                }
                return false;
            case RedirectMode.Honeypot:
                var normalized = NormalizePath(path);
                return _virtualFiles.ContainsKey(normalized) ||
                       _virtualBinaryFiles.ContainsKey(normalized) ||
                       (Redirector?.VirtualFileExists(path) ?? false);
            default:
                return false;
        }
    }

    public static IEnumerable<string> ReadLines(string path)
    {
        var content = ReadAllText(path);
        return content.Split('\n');
    }

    public static void AppendAllText(string path, string contents)
    {
        RecordAccess("APPEND_ALL_TEXT", path);
        switch (Mode)
        {
            case RedirectMode.Block:
                throw new SandboxException(ErrorCode.PathTraversal);
            case RedirectMode.Redirect:
                var redirectPath = Redirector?.RedirectPath(path);
                if (redirectPath != null)
                {
                    var full = Path.GetFullPath(Path.Combine(SandboxRoot, redirectPath));
                    Directory.CreateDirectory(Path.GetDirectoryName(full)!);
                    File.AppendAllText(full, contents);
                }
                break;
            case RedirectMode.Honeypot:
                var normalized = NormalizePath(path);
                var existing = _virtualFiles.TryGetValue(normalized, out var old) ? old : "";
                _virtualFiles[normalized] = existing + contents;
                break;
        }
    }

    public static bool DirectoryExists(string path)
    {
        RecordAccess("DIR_EXISTS", path);
        switch (Mode)
        {
            case RedirectMode.Block:
                throw new SandboxException(ErrorCode.PathTraversal);
            case RedirectMode.Honeypot:
                var normalized = NormalizePath(path);
                if (_virtualDirectories.ContainsKey(normalized))
                    return true;
                return Redirector?.VirtualDirectoryExists(path) ?? false;
            default:
                return false;
        }
    }

    public static string[] GetFiles(string path, string searchPattern)
    {
        RecordAccess("DIR_GET_FILES", path);
        switch (Mode)
        {
            case RedirectMode.Block:
                throw new SandboxException(ErrorCode.PathTraversal);
            case RedirectMode.Honeypot:
                return Redirector?.GetVirtualFiles(path, searchPattern)?.ToArray() ?? Array.Empty<string>();
            default:
                return Array.Empty<string>();
        }
    }

    public static string[] GetFiles(string path)
    {
        return GetFiles(path, "*");
    }

    public static string[] GetDirectories(string path)
    {
        RecordAccess("DIR_GET_DIRS", path);
        return Array.Empty<string>();
    }

    public static object CreateDirectory(string path)
    {
        RecordAccess("DIR_CREATE", path);
        switch (Mode)
        {
            case RedirectMode.Block:
                throw new SandboxException(ErrorCode.PathTraversal);
            case RedirectMode.Honeypot:
                _virtualDirectories[NormalizePath(path)] = true;
                return Directory.CreateDirectory(path);
            default:
                return Directory.CreateDirectory(path);
        }
    }

    public static IReadOnlyList<string> GetAccessLog() => _accessLog.AsReadOnly();

    private static void RecordAccess(string operation, string path)
    {
        _accessLog.Add($"[{DateTime.Now:HH:mm:ss}] {operation} -> {path}");
    }

    private static string NormalizePath(string path)
    {
        return path.TrimEnd('/', '\\');
    }

    private static void InitLinuxVirtualFS()
    {
        _virtualFiles["/etc/passwd"] = "root:x:0:0:root:/root:/bin/bash\nnobody:x:65534:65534:nobody:/nonexistent:/usr/sbin/nologin\nsandbox_user:x:1000:1000::/home/sandbox_user:/bin/bash\n";
        _virtualFiles["/etc/hosts"] = "127.0.0.1\tlocalhost\n::1\tlocalhost ip6-localhost\n";
        _virtualFiles["/etc/hostname"] = "sandbox-host\n";
        _virtualFiles["/etc/resolv.conf"] = "nameserver 8.8.8.8\nnameserver 8.8.4.4\n";
        _virtualFiles["/etc/os-release"] = "NAME=\"Ubuntu\"\nVERSION=\"22.04.3 LTS (Jammy Jellyfish)\"\nID=ubuntu\nID_LIKE=debian\nPRETTY_NAME=\"Ubuntu 22.04.3 LTS\"\nVERSION_ID=\"22.04\"\nHOME_URL=\"https://www.ubuntu.com/\"\nSUPPORT_URL=\"https://help.ubuntu.com/\"\nBUG_REPORT_URL=\"https://bugs.launchpad.net/ubuntu/\"\n";
        _virtualFiles["/etc/lsb-release"] = "DISTRIB_ID=Ubuntu\nDISTRIB_RELEASE=22.04\nDISTRIB_CODENAME=jammy\nDISTRIB_DESCRIPTION=\"Ubuntu 22.04.3 LTS\"\n";
        _virtualFiles["/proc/cpuinfo"] = "processor\t: 0\nvendor_id\t: GenuineIntel\ncpu family\t: 6\nmodel\t\t: 85\nmodel name\t: Intel(R) Xeon(R) CPU @ 2.60GHz\nstepping\t: 3\ncpu MHz\t\t: 2600.000\ncache size\t: 25600 KB\n";
        _virtualFiles["/proc/meminfo"] = "MemTotal:       16384000 kB\nMemFree:         8192000 kB\nMemAvailable:   12288000 kB\nBuffers:          512000 kB\nCached:          3072000 kB\n";
        _virtualFiles["/proc/version"] = "Linux version 6.5.0-44-generic (buildd@lcy02-amd64-051) (x86_64-linux-gnu-gcc-12 (Ubuntu 12.3.0-1ubuntu1~22.04) 12.3.0, GNU ld (GNU Binutils for Ubuntu) 2.38) #44~22.04.1-Ubuntu SMP x86_64\n";
        _virtualFiles["/proc/self/status"] = "Name:\tsandbox\nState:\tS (sleeping)\nPid:\t1000\nPPid:\t1\nUid:\t1000\t1000\t1000\t1000\nGid:\t1000\t1000\t1000\t1000\n";
        _virtualFiles["/proc/self/cmdline"] = "/app/sandbox.dll\0";
        _virtualFiles["/proc/self/environ"] = "HOME=/home/sandbox_user\0USER=sandbox_user\0PATH=/usr/local/bin:/usr/bin:/bin\0";
        _virtualFiles["/home/sandbox_user/.bashrc"] = "# ~/.bashrc\nexport PATH=$PATH:/usr/local/bin\nalias ll='ls -la'\n";
        _virtualFiles["/home/sandbox_user/.profile"] = "# ~/.profile\nif [ -n \"$BASH_VERSION\" ]; then\n    if [ -f \"$HOME/.bashrc\" ]; then\n        . \"$HOME/.bashrc\"\n    fi\nfi\n";
        _virtualFiles["/var/log/syslog"] = "Jan  1 00:00:01 sandbox-host systemd[1]: Started Session 1 of user sandbox_user.\n";
        _virtualFiles["/var/log/auth.log"] = "Jan  1 00:00:01 sandbox-host sshd[1234]: Accepted publickey for sandbox_user from 10.0.0.1\n";

        _virtualDirectories["/etc"] = true;
        _virtualDirectories["/home"] = true;
        _virtualDirectories["/home/sandbox_user"] = true;
        _virtualDirectories["/proc"] = true;
        _virtualDirectories["/proc/self"] = true;
        _virtualDirectories["/tmp"] = true;
        _virtualDirectories["/var"] = true;
        _virtualDirectories["/var/log"] = true;
        _virtualDirectories["/usr"] = true;
        _virtualDirectories["/usr/bin"] = true;
        _virtualDirectories["/usr/local"] = true;
        _virtualDirectories["/usr/local/bin"] = true;
        _virtualDirectories["/usr/share"] = true;
        _virtualDirectories["/opt"] = true;
    }
}
