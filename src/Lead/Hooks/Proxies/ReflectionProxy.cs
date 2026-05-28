namespace Lead.Hooks.Proxies;

public static class ReflectionProxy
{
    internal static RedirectMode Mode { get; set; } = RedirectMode.Honeypot;

    private static readonly List<string> AccessLog = new();

    public static object? Invoke(object methodInfo, object? obj, object?[]? parameters)
    {
        RecordAccess("METHOD_INVOKE", methodInfo.GetType().Name);
        switch (Mode)
        {
            case RedirectMode.Block:
                throw new SandboxException(ErrorCode.ForbiddenMethod);
            case RedirectMode.Honeypot:
                return null;
            default:
                return null;
        }
    }

    public static object? CreateInstance(Type type, params object?[]? args)
    {
        RecordAccess("ACTIVATOR_CREATE", type.Name);
        switch (Mode)
        {
            case RedirectMode.Block:
                throw new SandboxException(ErrorCode.ForbiddenMethod);
            case RedirectMode.Honeypot:
                try { return Activator.CreateInstance(type); }
                catch { return null; }
            default:
                return null;
        }
    }

    private static void RecordAccess(string operation, string target)
    {
        AccessLog.Add($"[{DateTime.Now:HH:mm:ss}] {operation} -> {target}");
    }

    public static IReadOnlyList<string> GetAccessLog() => AccessLog.AsReadOnly();
}
