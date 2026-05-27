using System.Text;
using System.Text.RegularExpressions;

namespace Lead;

public class VirtualFileRedirector : IFileRedirector
{
    private readonly Dictionary<string, string> _virtualFiles = new(StringComparer.OrdinalIgnoreCase);
    private readonly Dictionary<string, byte[]> _virtualBinaryFiles = new(StringComparer.OrdinalIgnoreCase);
    private readonly HashSet<string> _virtualDirectories = new(StringComparer.OrdinalIgnoreCase);
    private readonly Dictionary<string, string> _pathMappings = new(StringComparer.OrdinalIgnoreCase);
    private readonly List<(string Path, string Operation, DateTime Time)> _accessLog = new();
    private readonly Dictionary<string, string> _writtenFiles = new(StringComparer.OrdinalIgnoreCase);

    public VirtualFileRedirector()
    {
        InitDefaultVirtualFiles();
        InitDefaultPathMappings();
    }

    public string? RedirectPath(string originalPath)
    {
        var normalized = NormalizePath(originalPath);

        foreach (var mapping in _pathMappings)
        {
            if (normalized.StartsWith(mapping.Key, StringComparison.OrdinalIgnoreCase))
            {
                var relativePart = normalized[mapping.Key.Length..].TrimStart('\\', '/');
                return Path.Combine(mapping.Value, relativePart);
            }
        }

        return null;
    }

    public string? GetVirtualContent(string path)
    {
        var normalized = NormalizePath(path);
        RecordAccess(path, "READ_TEXT");

        if (_writtenFiles.TryGetValue(normalized, out var written))
            return written;

        return _virtualFiles.TryGetValue(normalized, out var content) ? content : null;
    }

    public byte[]? GetVirtualBinaryContent(string path)
    {
        var normalized = NormalizePath(path);
        RecordAccess(path, "READ_BINARY");

        if (_virtualBinaryFiles.TryGetValue(normalized, out var data))
            return data;

        var text = GetVirtualContent(path);
        return text != null ? Encoding.UTF8.GetBytes(text) : null;
    }

    public bool VirtualFileExists(string path)
    {
        var normalized = NormalizePath(path);
        return _virtualFiles.ContainsKey(normalized) ||
               _virtualBinaryFiles.ContainsKey(normalized) ||
               _writtenFiles.ContainsKey(normalized);
    }

    public bool VirtualDirectoryExists(string path)
    {
        var normalized = NormalizePath(path);
        if (_virtualDirectories.Contains(normalized))
            return true;

        var prefix = normalized.EndsWith('\\') || normalized.EndsWith('/')
            ? normalized
            : normalized + "\\";

        return _virtualFiles.Keys.Any(k => k.StartsWith(prefix, StringComparison.OrdinalIgnoreCase)) ||
               _virtualBinaryFiles.Keys.Any(k => k.StartsWith(prefix, StringComparison.OrdinalIgnoreCase));
    }

    public IEnumerable<string> GetVirtualFiles(string directory, string pattern)
    {
        var normalized = NormalizePath(directory);
        var prefix = normalized.EndsWith('\\') || normalized.EndsWith('/')
            ? normalized
            : normalized + "\\";

        var allPaths = _virtualFiles.Keys
            .Concat(_virtualBinaryFiles.Keys)
            .Concat(_writtenFiles.Keys)
            .Where(k => k.StartsWith(prefix, StringComparison.OrdinalIgnoreCase))
            .Select(k => k[prefix.Length..])
            .Where(k => !string.IsNullOrEmpty(k))
            .Distinct();

        if (pattern == "*")
            return allPaths.ToList();

        var regex = GlobToRegex(pattern);
        return allPaths.Where(f => regex.IsMatch(f)).ToList();
    }

    public void RecordWrite(string path, string content)
    {
        var normalized = NormalizePath(path);
        _writtenFiles[normalized] = content;
        RecordAccess(path, "WRITE_TEXT");
    }

    public void RecordWrite(string path, byte[] data)
    {
        var normalized = NormalizePath(path);
        _virtualBinaryFiles[normalized] = data;
        RecordAccess(path, "WRITE_BINARY");
    }

    public void RecordAccess(string path, string operation)
    {
        _accessLog.Add((path, operation, DateTime.UtcNow));
    }

    public IReadOnlyList<(string Path, string Operation, DateTime Time)> GetAccessLog() => _accessLog;

    public void AddVirtualFile(string path, string content)
    {
        _virtualFiles[NormalizePath(path)] = content;
        EnsureDirectoryExists(NormalizePath(path));
    }

    public void AddVirtualBinaryFile(string path, byte[] data)
    {
        _virtualBinaryFiles[NormalizePath(path)] = data;
        EnsureDirectoryExists(NormalizePath(path));
    }

    public void AddPathMapping(string originalPrefix, string sandboxTarget)
    {
        _pathMappings[NormalizePath(originalPrefix)] = sandboxTarget;
    }

    private void EnsureDirectoryExists(string filePath)
    {
        var dir = Path.GetDirectoryName(filePath);
        while (!string.IsNullOrEmpty(dir))
        {
            _virtualDirectories.Add(dir);
            dir = Path.GetDirectoryName(dir);
        }
    }

    private static string NormalizePath(string path)
    {
        return path.Replace('/', '\\').TrimEnd('\\');
    }

    private static Regex GlobToRegex(string pattern)
    {
        var regexStr = "^" + Regex.Escape(pattern)
            .Replace("\\*\\*", ".*")
            .Replace("\\*", "[^\\\\]*")
            .Replace("\\?", ".") + "$";
        return new Regex(regexStr, RegexOptions.IgnoreCase);
    }

    private void InitDefaultVirtualFiles()
    {
        AddVirtualFile(@"C:\Windows\win.ini", "; for 16-bit app support\n[fonts]\n[extensions]\n[mci extensions]\n[files]\n[Mail]\nMAPI=1\n");
        AddVirtualFile(@"C:\Windows\system.ini", "; system.ini\n[boot]\nshell=explorer.exe\n[386Enh]\nwoafont=dosapp.fon\n");
        AddVirtualFile(@"C:\Windows\explorer.exe", "");
        AddVirtualFile(@"C:\Windows\notepad.exe", "");
        AddVirtualFile(@"C:\Windows\System32\drivers\etc\hosts", "# Copyright (c) 1993-2009 Microsoft Corp.\n#\n# This is a sample HOSTS file.\n127.0.0.1       localhost\n::1             localhost\n");
        AddVirtualFile(@"C:\Windows\System32\cmd.exe", "");
        AddVirtualFile(@"C:\Windows\System32\ntdll.dll", "");
        AddVirtualFile(@"C:\Windows\System32\kernel32.dll", "");
        AddVirtualFile(@"C:\Windows\System32\user32.dll", "");
        AddVirtualFile(@"C:\Users\Public\desktop.ini", "[.ShellClassInfo]\nIconResource=C:\\Windows\\system32\\imageres.dll,-1023\n");
        AddVirtualFile(@"C:\Program Files\desktop.ini", "[.ShellClassInfo]\nIconResource=C:\\Windows\\system32\\shell32.dll,-2\n");
        AddVirtualFile(@"C:\ProgramData\desktop.ini", "[.ShellClassInfo]\nIconResource=C:\\Windows\\system32\\shell32.dll,-2\n");
        AddVirtualFile(@"/etc/passwd", "root:x:0:0:root:/root:/bin/bash\ndaemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin\nnobody:x:65534:65534:nobody:/nonexistent:/usr/sbin/nologin\n");
        AddVirtualFile(@"/etc/hosts", "127.0.0.1\tlocalhost\n::1\tlocalhost ip6-localhost\n");
        AddVirtualFile(@"/etc/hostname", "sandbox-host\n");
        AddVirtualFile(@"/etc/resolv.conf", "nameserver 8.8.8.8\nnameserver 8.8.4.4\n");

        _virtualDirectories.Add(NormalizePath(@"C:\Windows"));
        _virtualDirectories.Add(NormalizePath(@"C:\Windows\System32"));
        _virtualDirectories.Add(NormalizePath(@"C:\Windows\System32\drivers"));
        _virtualDirectories.Add(NormalizePath(@"C:\Windows\System32\drivers\etc"));
        _virtualDirectories.Add(NormalizePath(@"C:\Users"));
        _virtualDirectories.Add(NormalizePath(@"C:\Users\Public"));
        _virtualDirectories.Add(NormalizePath(@"C:\Program Files"));
        _virtualDirectories.Add(NormalizePath(@"C:\ProgramData"));
        _virtualDirectories.Add(NormalizePath(@"C:\Temp"));
        _virtualDirectories.Add(NormalizePath(@"/etc"));
        _virtualDirectories.Add(NormalizePath(@"/tmp"));
        _virtualDirectories.Add(NormalizePath(@"/var"));
        _virtualDirectories.Add(NormalizePath(@"/var/log"));
    }

    private void InitDefaultPathMappings()
    {
        _pathMappings[NormalizePath(@"C:\Windows")] = "windows";
        _pathMappings[NormalizePath(@"C:\Users")] = "users";
        _pathMappings[NormalizePath(@"C:\Program Files")] = "program_files";
        _pathMappings[NormalizePath(@"C:\ProgramData")] = "programdata";
        _pathMappings[NormalizePath(@"C:\Temp")] = "temp";
        _pathMappings[NormalizePath(@"/etc")] = "etc";
        _pathMappings[NormalizePath(@"/tmp")] = "tmp";
        _pathMappings[NormalizePath(@"/var")] = "var";
    }
}
