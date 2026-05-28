namespace Lead.Hooks;

public class MethodHookDispatcher
{
    private readonly List<IMethodHook> _hooks = new();
    private Dictionary<string, List<MethodHookRule>>? _ruleCache;

    public void Register(IMethodHook hook)
    {
        _hooks.Add(hook);
        _ruleCache = null;
    }

    public void Register(IEnumerable<IMethodHook> hooks)
    {
        _hooks.AddRange(hooks);
        _ruleCache = null;
    }

    public MethodHookRule? FindRule(string typeFullName, string methodName)
    {
        EnsureCache();
        var key = $"{typeFullName}::{methodName}";
        if (_ruleCache!.TryGetValue(key, out var rules) && rules.Count > 0)
            return rules[0];
        return null;
    }

    public IReadOnlyList<MethodHookRule> GetAllRules()
    {
        EnsureCache();
        return _ruleCache!.Values.SelectMany(r => r).ToList().AsReadOnly();
    }

    public IReadOnlyList<MethodHookRule> GetRulesByCategory(string category)
    {
        return _hooks.Where(h => h.Category == category).SelectMany(h => h.GetRules()).ToList().AsReadOnly();
    }

    private void EnsureCache()
    {
        if (_ruleCache != null) return;

        _ruleCache = new Dictionary<string, List<MethodHookRule>>();
        foreach (var hook in _hooks)
        {
            foreach (var rule in hook.GetRules())
            {
                var key = $"{rule.OriginalType}::{rule.OriginalMethod}";
                if (!_ruleCache.ContainsKey(key))
                    _ruleCache[key] = new List<MethodHookRule>();
                _ruleCache[key].Add(rule);
            }
        }
    }
}
