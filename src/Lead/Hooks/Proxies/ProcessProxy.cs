namespace Lead.Hooks.Proxies;

public static class ProcessProxy
{
    internal static RedirectMode Mode { get; set; } = RedirectMode.Honeypot;

    private static readonly List<string> AccessLog = new();

    public static void Start()
    {
        RecordAccess("PROCESS_START");
        switch (Mode)
        {
            case RedirectMode.Block:
                throw new SandboxException(ErrorCode.ForbiddenType);
            case RedirectMode.Honeypot:
                break;
        }
    }

    public static void Kill()
    {
        RecordAccess("PROCESS_KILL");
        switch (Mode)
        {
            case RedirectMode.Block:
                throw new SandboxException(ErrorCode.ForbiddenType);
            case RedirectMode.Honeypot:
                break;
        }
    }

    private static void RecordAccess(string operation)
    {
        AccessLog.Add($"[{DateTime.Now:HH:mm:ss}] {operation}");
    }

    public static IReadOnlyList<string> GetAccessLog() => AccessLog.AsReadOnly();
}
