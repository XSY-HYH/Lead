namespace Lead;

public class ExecutionResult
{
    public bool Success { get; init; }
    public string? Error { get; init; }
    public bool Cancelled { get; init; }

    public static ExecutionResult Succeeded()
    {
        return new ExecutionResult { Success = true };
    }

    public static ExecutionResult Failed(string error)
    {
        return new ExecutionResult { Success = false, Error = error };
    }

    public static ExecutionResult WasCancelled()
    {
        return new ExecutionResult { Success = false, Cancelled = true };
    }
}
