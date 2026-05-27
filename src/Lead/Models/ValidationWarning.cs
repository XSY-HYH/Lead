namespace Lead;

public class ValidationWarning
{
    public string Location { get; }
    public string Message { get; }
    public Severity Severity { get; }

    public ValidationWarning(string location, string message, Severity severity)
    {
        Location = location;
        Message = message;
        Severity = severity;
    }
}
