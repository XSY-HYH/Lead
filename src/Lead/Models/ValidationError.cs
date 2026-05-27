namespace Lead;

public class ValidationError
{
    public string Location { get; }
    public string Message { get; }
    public Severity Severity { get; }

    public ValidationError(string location, string message, Severity severity)
    {
        Location = location;
        Message = message;
        Severity = severity;
    }
}
