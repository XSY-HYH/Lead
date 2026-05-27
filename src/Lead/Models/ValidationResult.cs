namespace Lead;

public class ValidationResult
{
    public bool IsValid { get; init; }
    public IReadOnlyList<ValidationError> Errors { get; init; } = Array.Empty<ValidationError>();
    public IReadOnlyList<ValidationWarning> Warnings { get; init; } = Array.Empty<ValidationWarning>();

    public static ValidationResult Error(string message)
    {
        return new ValidationResult
        {
            IsValid = false,
            Errors = new List<ValidationError> { new("Assembly", message, Severity.Error) }
        };
    }
}
