namespace Lead;

public interface IFileService
{
    Task<string> ReadTextFileAsync(string path, CancellationToken ct = default);
    Task WriteTextFileAsync(string path, string content, CancellationToken ct = default);
    Task<byte[]> ReadBinaryFileAsync(string path, CancellationToken ct = default);
    Task WriteBinaryFileAsync(string path, byte[] data, CancellationToken ct = default);
    bool FileExists(string path);
    bool DirectoryExists(string path);
    IEnumerable<string> GetFiles(string directory, string pattern = "*");
}
