namespace Lead;

public interface IFileRedirector
{
    string? RedirectPath(string originalPath);
    string? GetVirtualContent(string path);
    byte[]? GetVirtualBinaryContent(string path);
    bool VirtualFileExists(string path);
    bool VirtualDirectoryExists(string path);
    IEnumerable<string> GetVirtualFiles(string directory, string pattern);
    void RecordWrite(string path, string content);
    void RecordWrite(string path, byte[] data);
    void RecordAccess(string path, string operation);
}
