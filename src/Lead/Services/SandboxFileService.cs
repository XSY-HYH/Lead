using System.Text.RegularExpressions;

namespace Lead;

public class SandboxFileService : IFileService
{
    private readonly string _pluginId;
    private readonly SandboxConfiguration _config;
    private readonly RedirectMode _redirectMode;
    private readonly IFileRedirector? _redirector;
    private long _bytesRead;
    private long _bytesWritten;

    public SandboxFileService(string pluginId, SandboxConfiguration config)
    {
        _pluginId = pluginId;
        _config = config;
        _redirectMode = config.FileRedirectMode;
        _redirector = config.FileRedirector;
    }

    public async Task<string> ReadTextFileAsync(string path, CancellationToken ct = default)
    {
        CheckResourceLimits();

        if (IsSandboxPath(path))
            return await ReadSandboxFileAsync(path, ct);

        return _redirectMode switch
        {
            RedirectMode.Block => throw new SandboxException(ErrorCode.PathTraversal),
            RedirectMode.Redirect => await ReadRedirectedAsync(path, ct),
            RedirectMode.Honeypot => ReadHoneypot(path),
            _ => throw new SandboxException(ErrorCode.PathTraversal)
        };
    }

    public async Task WriteTextFileAsync(string path, string content, CancellationToken ct = default)
    {
        CheckResourceLimits();

        if (content.Length > _config.MaxFileSize)
        {
            if (_redirectMode == RedirectMode.Honeypot)
            {
                _redirector?.RecordWrite(path, content);
                return;
            }
            throw new SandboxException(ErrorCode.FileTooLarge);
        }

        if (IsSandboxPath(path))
        {
            await WriteSandboxFileAsync(path, content, ct);
            return;
        }

        switch (_redirectMode)
        {
            case RedirectMode.Block:
                throw new SandboxException(ErrorCode.PathTraversal);
            case RedirectMode.Redirect:
                await WriteRedirectedAsync(path, content, ct);
                break;
            case RedirectMode.Honeypot:
                _redirector?.RecordWrite(path, content);
                break;
        }
    }

    public async Task<byte[]> ReadBinaryFileAsync(string path, CancellationToken ct = default)
    {
        CheckResourceLimits();

        if (IsSandboxPath(path))
        {
            var fullPath = ResolveSandboxPath(path);
            if (!File.Exists(fullPath))
                throw new SandboxException(ErrorCode.PathTraversal);
            var data = await File.ReadAllBytesAsync(fullPath, ct);
            Interlocked.Add(ref _bytesRead, data.Length);
            return data;
        }

        return _redirectMode switch
        {
            RedirectMode.Block => throw new SandboxException(ErrorCode.PathTraversal),
            RedirectMode.Redirect => await ReadBinaryRedirectedAsync(path, ct),
            RedirectMode.Honeypot => ReadBinaryHoneypot(path),
            _ => throw new SandboxException(ErrorCode.PathTraversal)
        };
    }

    public async Task WriteBinaryFileAsync(string path, byte[] data, CancellationToken ct = default)
    {
        CheckResourceLimits();

        if (data.Length > _config.MaxFileSize)
        {
            if (_redirectMode == RedirectMode.Honeypot)
            {
                _redirector?.RecordWrite(path, data);
                return;
            }
            throw new SandboxException(ErrorCode.FileTooLarge);
        }

        if (IsSandboxPath(path))
        {
            var fullPath = ResolveSandboxPath(path);
            EnsureDirectory(fullPath);
            await File.WriteAllBytesAsync(fullPath, data, ct);
            Interlocked.Add(ref _bytesWritten, data.Length);
            return;
        }

        switch (_redirectMode)
        {
            case RedirectMode.Block:
                throw new SandboxException(ErrorCode.PathTraversal);
            case RedirectMode.Redirect:
                var redirectPath = GetRedirectWritePath(path);
                EnsureDirectory(redirectPath);
                await File.WriteAllBytesAsync(redirectPath, data, ct);
                Interlocked.Add(ref _bytesWritten, data.Length);
                break;
            case RedirectMode.Honeypot:
                _redirector?.RecordWrite(path, data);
                break;
        }
    }

    public bool FileExists(string path)
    {
        if (IsSandboxPath(path))
            return File.Exists(ResolveSandboxPath(path));

        return _redirectMode switch
        {
            RedirectMode.Block => false,
            RedirectMode.Redirect => _redirector?.VirtualFileExists(path) ?? false,
            RedirectMode.Honeypot => _redirector?.VirtualFileExists(path) ?? false,
            _ => false
        };
    }

    public bool DirectoryExists(string path)
    {
        if (IsSandboxPath(path))
            return Directory.Exists(ResolveSandboxPath(path));

        return _redirectMode switch
        {
            RedirectMode.Block => false,
            RedirectMode.Redirect => _redirector?.VirtualDirectoryExists(path) ?? false,
            RedirectMode.Honeypot => _redirector?.VirtualDirectoryExists(path) ?? false,
            _ => false
        };
    }

    public IEnumerable<string> GetFiles(string directory, string pattern = "*")
    {
        if (IsSandboxPath(directory))
        {
            var fullPath = ResolveSandboxPath(directory);
            if (!Directory.Exists(fullPath))
                return Enumerable.Empty<string>();
            return Directory.GetFiles(fullPath, pattern)
                .Select(f => Path.GetRelativePath(fullPath, f))
                .ToArray();
        }

        return _redirectMode switch
        {
            RedirectMode.Block => Enumerable.Empty<string>(),
            RedirectMode.Redirect => _redirector?.GetVirtualFiles(directory, pattern) ?? Enumerable.Empty<string>(),
            RedirectMode.Honeypot => _redirector?.GetVirtualFiles(directory, pattern) ?? Enumerable.Empty<string>(),
            _ => Enumerable.Empty<string>()
        };
    }

    private bool IsSandboxPath(string path)
    {
        if (string.IsNullOrWhiteSpace(path)) return false;
        if (path.Contains("..")) return false;
        if (Path.IsPathRooted(path)) return false;

        var ext = Path.GetExtension(path).ToLowerInvariant();
        if (ext != "" && !_config.AllowedFileExtensions.Contains(ext))
            return false;

        return true;
    }

    private async Task<string> ReadSandboxFileAsync(string path, CancellationToken ct)
    {
        var fullPath = ResolveSandboxPath(path);
        if (!File.Exists(fullPath))
            throw new SandboxException(ErrorCode.PathTraversal);

        var content = await File.ReadAllTextAsync(fullPath, System.Text.Encoding.UTF8, ct);
        Interlocked.Add(ref _bytesRead, content.Length);
        return content;
    }

    private async Task WriteSandboxFileAsync(string path, string content, CancellationToken ct)
    {
        var fullPath = ResolveSandboxPath(path);
        EnsureDirectory(fullPath);
        await File.WriteAllTextAsync(fullPath, content, System.Text.Encoding.UTF8, ct);
        Interlocked.Add(ref _bytesWritten, content.Length);
    }

    private async Task<string> ReadRedirectedAsync(string path, CancellationToken ct)
    {
        var redirectPath = _redirector?.RedirectPath(path);
        if (redirectPath != null)
        {
            var sandboxPath = Path.GetFullPath(Path.Combine(_config.SandboxRootDirectory, _pluginId, "vfs", redirectPath));
            if (File.Exists(sandboxPath))
            {
                var content = await File.ReadAllTextAsync(sandboxPath, System.Text.Encoding.UTF8, ct);
                Interlocked.Add(ref _bytesRead, content.Length);
                return content;
            }
        }

        var virtualContent = _redirector?.GetVirtualContent(path);
        if (virtualContent != null)
        {
            Interlocked.Add(ref _bytesRead, virtualContent.Length);
            return virtualContent;
        }

        throw new SandboxException(ErrorCode.PathTraversal);
    }

    private string ReadHoneypot(string path)
    {
        _redirector?.RecordAccess(path, "READ_TEXT");
        var content = _redirector?.GetVirtualContent(path);
        if (content != null)
        {
            Interlocked.Add(ref _bytesRead, content.Length);
            return content;
        }

        return "";
    }

    private async Task<byte[]> ReadBinaryRedirectedAsync(string path, CancellationToken ct)
    {
        var redirectPath = _redirector?.RedirectPath(path);
        if (redirectPath != null)
        {
            var sandboxPath = Path.GetFullPath(Path.Combine(_config.SandboxRootDirectory, _pluginId, "vfs", redirectPath));
            if (File.Exists(sandboxPath))
            {
                var data = await File.ReadAllBytesAsync(sandboxPath, ct);
                Interlocked.Add(ref _bytesRead, data.Length);
                return data;
            }
        }

        var virtualData = _redirector?.GetVirtualBinaryContent(path);
        if (virtualData != null)
        {
            Interlocked.Add(ref _bytesRead, virtualData.Length);
            return virtualData;
        }

        throw new SandboxException(ErrorCode.PathTraversal);
    }

    private byte[] ReadBinaryHoneypot(string path)
    {
        _redirector?.RecordAccess(path, "READ_BINARY");
        var data = _redirector?.GetVirtualBinaryContent(path);
        if (data != null)
        {
            Interlocked.Add(ref _bytesRead, data.Length);
            return data;
        }
        return Array.Empty<byte>();
    }

    private async Task WriteRedirectedAsync(string path, string content, CancellationToken ct)
    {
        var redirectPath = GetRedirectWritePath(path);
        EnsureDirectory(redirectPath);
        await File.WriteAllTextAsync(redirectPath, content, System.Text.Encoding.UTF8, ct);
        Interlocked.Add(ref _bytesWritten, content.Length);
    }

    private string GetRedirectWritePath(string path)
    {
        var redirectPath = _redirector?.RedirectPath(path) ?? "unknown";
        return Path.GetFullPath(Path.Combine(_config.SandboxRootDirectory, _pluginId, "vfs", redirectPath));
    }

    private string ResolveSandboxPath(string relativePath)
    {
        var workDir = Path.GetFullPath(Path.Combine(_config.SandboxRootDirectory, _pluginId));
        Directory.CreateDirectory(workDir);

        var fullPath = Path.GetFullPath(Path.Combine(workDir, relativePath));

        if (!fullPath.StartsWith(workDir, StringComparison.OrdinalIgnoreCase))
            throw new SandboxException(ErrorCode.PathEscape);

        return fullPath;
    }

    private static void EnsureDirectory(string filePath)
    {
        var dir = Path.GetDirectoryName(filePath);
        if (!string.IsNullOrEmpty(dir))
            Directory.CreateDirectory(dir);
    }

    private void CheckResourceLimits()
    {
        if (_bytesRead > _config.MaxBytesRead)
            throw new SandboxException(ErrorCode.ReadLimitExceeded);

        if (_bytesWritten > _config.MaxBytesWritten)
            throw new SandboxException(ErrorCode.WriteLimitExceeded);
    }
}
