using System.Reflection;

namespace Lead;

public class PluginProxy : IPluginProxy
{
    private readonly ISandboxedPlugin _plugin;
    private readonly MethodInfo[] _methods;

    public PluginProxy(ISandboxedPlugin plugin)
    {
        _plugin = plugin;
        _methods = plugin.GetType().GetMethods(BindingFlags.Public | BindingFlags.Instance);
    }

    public async Task<TResult> CallAsync<TResult>(string methodName, object[]? args)
    {
        var method = _methods.FirstOrDefault(m => m.Name == methodName);
        if (method == null)
            throw new ArgumentException($"Method not found: {methodName}");

        var parameters = method.GetParameters();
        if (parameters.Length != args?.Length)
            throw new ArgumentException("Parameter count mismatch");

        for (int i = 0; i < parameters.Length; i++)
        {
            var arg = args?[i];
            if (arg != null && !IsSafeType(arg.GetType()))
                throw new SandboxException(ErrorCode.UnsafeParamType);
        }

        var result = method.Invoke(_plugin, args);

        if (result is Task taskResult)
        {
            await taskResult;
            if (taskResult is Task<TResult> typedTask)
                return await typedTask;
            return default!;
        }

        return (TResult)result!;
    }

    private static bool IsSafeType(Type type)
    {
        if (type.IsPrimitive || type == typeof(string))
            return true;

        if (type == typeof(DateTime) || type == typeof(TimeSpan) || type == typeof(Guid))
            return true;

        if (type.IsGenericType)
        {
            var genericDef = type.GetGenericTypeDefinition();
            if (genericDef == typeof(List<>) || genericDef == typeof(Dictionary<,>))
                return true;
        }

        return false;
    }
}
