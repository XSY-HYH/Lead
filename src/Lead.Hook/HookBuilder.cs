namespace Lead.Hook;

public sealed class HookBuilder
{
    private readonly List<HookRule> _rules = new();

    public HookTargetBuilder Hook(string typeFullName, string methodName)
    {
        return new HookTargetBuilder(this, typeFullName, methodName, HookType.CallSite);
    }

    public HookTargetBuilder Hook(string typeFullName, string methodName, HookType hookType)
    {
        return new HookTargetBuilder(this, typeFullName, methodName, hookType);
    }

    public HookTargetBuilder Hook<TTarget>(string methodName)
    {
        return new HookTargetBuilder(this, typeof(TTarget).FullName!, methodName, HookType.CallSite);
    }

    public HookTargetBuilder Hook<TTarget>(string methodName, HookType hookType)
    {
        return new HookTargetBuilder(this, typeof(TTarget).FullName!, methodName, hookType);
    }

    public HookBuilder AddRule(HookRule rule)
    {
        _rules.Add(rule);
        return this;
    }

    public HookBuilder AddRules(IEnumerable<HookRule> rules)
    {
        _rules.AddRange(rules);
        return this;
    }

    public HookEngine Build()
    {
        var engine = new HookEngine();
        engine.AddRules(_rules);
        return engine;
    }

    internal void RegisterRule(HookRule rule)
    {
        _rules.Add(rule);
    }
}

public sealed class HookTargetBuilder
{
    private readonly HookBuilder _parent;
    private readonly string _typeFullName;
    private readonly string _methodName;
    private readonly HookType _hookType;

    internal HookTargetBuilder(HookBuilder parent, string typeFullName, string methodName, HookType hookType)
    {
        _parent = parent;
        _typeFullName = typeFullName;
        _methodName = methodName;
        _hookType = hookType;
    }

    public HookBuilder With(Type replacementType, string replacementMethod, string? description = null)
    {
        _parent.RegisterRule(new HookRule(_typeFullName, _methodName, replacementType, replacementMethod, _hookType, description));
        return _parent;
    }
}
