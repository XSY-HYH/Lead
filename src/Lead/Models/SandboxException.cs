namespace Lead;

public class SandboxException : Exception
{
    public string Code { get; }

    public SandboxException(string code) : base(code)
    {
        Code = code;
    }

    public SandboxException(string code, Exception innerException) : base(code, innerException)
    {
        Code = code;
    }
}
