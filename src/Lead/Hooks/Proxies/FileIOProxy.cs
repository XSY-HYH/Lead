namespace Lead.Hooks.Proxies;

public static class FileIOProxy
{
    internal static RedirectMode Mode { get; set; } = RedirectMode.Honeypot;
    internal static IFileRedirector? Redirector { get; set; }
    internal static string SandboxRoot { get; set; } = "./sandbox_data";

    private static readonly List<string> AccessLog = new();

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
                return Redirector?.VirtualFileExists(path) ?? false;
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
            case RedirectMode.Honeypot:
                break;
            case RedirectMode.Redirect:
                var redirectPath = Redirector?.RedirectPath(path);
                if (redirectPath != null)
                {
                    var full = Path.GetFullPath(Path.Combine(SandboxRoot, redirectPath));
                    Directory.CreateDirectory(Path.GetDirectoryName(full)!);
                    File.AppendAllText(full, contents);
                }
                break;
        }
    }

    private static void RecordAccess(string operation, string path)
    {
        AccessLog.Add($"[{DateTime.Now:HH:mm:ss}] {operation} -> {path}");
    }

    public static IReadOnlyList<string> GetAccessLog() => AccessLog.AsReadOnly();
}
