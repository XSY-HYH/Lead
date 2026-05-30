namespace Lead.Hook;

public enum HookType
{
    CallSite,
    MethodBody,
    NewObj,
    FieldRead,
    FieldWrite,
    TypeCheck,
    Box,
    FunctionPointer,
}

public sealed class HookRule
{
    public string OriginalType { get; }
    public string OriginalMethod { get; }
    public Type ReplacementType { get; }
    public string ReplacementMethod { get; }
    public HookType HookType { get; }
    public string? Description { get; }

    public HookRule(string originalType, string originalMethod, Type replacementType, string replacementMethod, HookType hookType = HookType.CallSite, string? description = null)
    {
        OriginalType = originalType ?? throw new ArgumentNullException(nameof(originalType));
        OriginalMethod = originalMethod ?? throw new ArgumentNullException(nameof(originalMethod));
        ReplacementType = replacementType ?? throw new ArgumentNullException(nameof(replacementType));
        ReplacementMethod = replacementMethod ?? throw new ArgumentNullException(nameof(replacementMethod));
        HookType = hookType;
        Description = description;
    }

    public override string ToString()
    {
        var prefix = HookType switch
        {
            HookType.CallSite => "[CallSite] ",
            HookType.MethodBody => "[MethodBody] ",
            HookType.NewObj => "[NewObj] ",
            HookType.FieldRead => "[FieldRead] ",
            HookType.FieldWrite => "[FieldWrite] ",
            HookType.TypeCheck => "[TypeCheck] ",
            HookType.Box => "[Box] ",
            HookType.FunctionPointer => "[FuncPtr] ",
            _ => ""
        };
        return $"{prefix}{OriginalType}::{OriginalMethod} → {ReplacementType.FullName}::{ReplacementMethod}";
    }
}
