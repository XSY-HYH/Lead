using System.Reflection;

namespace Lead.EnvironmentManagement;

public class RuntimeInspector
{
    private readonly Assembly _assembly;
    private readonly string _pluginId;

    public Assembly TargetAssembly => _assembly;
    public string PluginId => _pluginId;

    internal RuntimeInspector(Assembly assembly, string pluginId)
    {
        _assembly = assembly;
        _pluginId = pluginId;
    }

    public IReadOnlyList<TypeInfo> GetLoadedTypes()
    {
        return _assembly.DefinedTypes.ToList().AsReadOnly();
    }

    public TypeInfo? FindType(string typeName)
    {
        return _assembly.DefinedTypes.FirstOrDefault(t => t.Name == typeName || t.FullName == typeName);
    }

    public IReadOnlyList<FieldInfo> GetStaticFields(string typeName)
    {
        var type = FindType(typeName);
        if (type == null) return Array.Empty<FieldInfo>().AsReadOnly();

        return type.DeclaredFields
            .Where(f => f.IsStatic)
            .ToList().AsReadOnly();
    }

    public IReadOnlyList<PropertyInfo> GetStaticProperties(string typeName)
    {
        var type = FindType(typeName);
        if (type == null) return Array.Empty<PropertyInfo>().AsReadOnly();

        return type.DeclaredProperties
            .Where(p => p.GetMethod?.IsStatic == true)
            .ToList().AsReadOnly();
    }

    public object? GetStaticFieldValue(string typeName, string fieldName)
    {
        var type = FindType(typeName);
        if (type == null) throw new InvalidOperationException($"Type '{typeName}' not found");

        var field = type.DeclaredFields.FirstOrDefault(f => f.Name == fieldName && f.IsStatic);
        if (field == null) throw new InvalidOperationException($"Static field '{fieldName}' not found in '{typeName}'");

        return field.GetValue(null);
    }

    public void SetStaticFieldValue(string typeName, string fieldName, object? value)
    {
        var type = FindType(typeName);
        if (type == null) throw new InvalidOperationException($"Type '{typeName}' not found");

        var field = type.DeclaredFields.FirstOrDefault(f => f.Name == fieldName && f.IsStatic);
        if (field == null) throw new InvalidOperationException($"Static field '{fieldName}' not found in '{typeName}'");

        if (field.IsInitOnly)
            throw new InvalidOperationException($"Field '{fieldName}' is init-only (readonly)");

        field.SetValue(null, value);
    }

    public object? GetStaticPropertyValue(string typeName, string propertyName)
    {
        var type = FindType(typeName);
        if (type == null) throw new InvalidOperationException($"Type '{typeName}' not found");

        var prop = type.DeclaredProperties.FirstOrDefault(p => p.Name == propertyName && p.GetMethod?.IsStatic == true);
        if (prop == null) throw new InvalidOperationException($"Static property '{propertyName}' not found in '{typeName}'");

        return prop.GetValue(null);
    }

    public void SetStaticPropertyValue(string typeName, string propertyName, object? value)
    {
        var type = FindType(typeName);
        if (type == null) throw new InvalidOperationException($"Type '{typeName}' not found");

        var prop = type.DeclaredProperties.FirstOrDefault(p => p.Name == propertyName && p.SetMethod?.IsStatic == true);
        if (prop == null) throw new InvalidOperationException($"Static property '{propertyName}' not found or has no setter in '{typeName}'");

        prop.SetValue(null, value);
    }

    public Dictionary<string, object?> GetAllStaticValues(string typeName)
    {
        var result = new Dictionary<string, object?>();
        var type = FindType(typeName);
        if (type == null) return result;

        foreach (var field in type.DeclaredFields.Where(f => f.IsStatic && !f.IsInitOnly))
        {
            try { result[$"field:{field.Name}"] = field.GetValue(null); }
            catch { result[$"field:{field.Name}"] = "<error>"; }
        }

        foreach (var prop in type.DeclaredProperties.Where(p => p.GetMethod?.IsStatic == true))
        {
            try { result[$"prop:{prop.Name}"] = prop.GetValue(null); }
            catch { result[$"prop:{prop.Name}"] = "<error>"; }
        }

        return result;
    }

    public object? InvokeStaticMethod(string typeName, string methodName, params object?[]? args)
    {
        var type = FindType(typeName);
        if (type == null) throw new InvalidOperationException($"Type '{typeName}' not found");

        var method = type.DeclaredMethods.FirstOrDefault(m =>
            m.Name == methodName && m.IsStatic && m.GetParameters().Length == (args?.Length ?? 0));
        if (method == null) throw new InvalidOperationException($"Static method '{methodName}' with matching parameters not found in '{typeName}'");

        return method.Invoke(null, args);
    }

    public IReadOnlyList<MethodInfo> GetStaticMethods(string typeName)
    {
        var type = FindType(typeName);
        if (type == null) return Array.Empty<MethodInfo>().AsReadOnly();

        return type.DeclaredMethods
            .Where(m => m.IsStatic && m.IsPublic)
            .ToList().AsReadOnly();
    }

    public object CreateInstance(string typeName, params object?[]? args)
    {
        var type = FindType(typeName);
        if (type == null) throw new InvalidOperationException($"Type '{typeName}' not found");

        return Activator.CreateInstance(type.AsType(), args)
            ?? throw new InvalidOperationException($"Failed to create instance of '{typeName}'");
    }

    public object? GetInstanceFieldValue(object instance, string fieldName)
    {
        var type = instance.GetType();
        var field = type.GetField(fieldName, BindingFlags.Public | BindingFlags.NonPublic | BindingFlags.Instance);
        if (field == null) throw new InvalidOperationException($"Field '{fieldName}' not found in '{type.Name}'");

        return field.GetValue(instance);
    }

    public void SetInstanceFieldValue(object instance, string fieldName, object? value)
    {
        var type = instance.GetType();
        var field = type.GetField(fieldName, BindingFlags.Public | BindingFlags.NonPublic | BindingFlags.Instance);
        if (field == null) throw new InvalidOperationException($"Field '{fieldName}' not found in '{type.Name}'");

        if (field.IsInitOnly)
            throw new InvalidOperationException($"Field '{fieldName}' is init-only (readonly)");

        field.SetValue(instance, value);
    }

    public object? GetInstancePropertyValue(object instance, string propertyName)
    {
        var type = instance.GetType();
        var prop = type.GetProperty(propertyName, BindingFlags.Public | BindingFlags.NonPublic | BindingFlags.Instance);
        if (prop == null) throw new InvalidOperationException($"Property '{propertyName}' not found in '{type.Name}'");

        return prop.GetValue(instance);
    }

    public void SetInstancePropertyValue(object instance, string propertyName, object? value)
    {
        var type = instance.GetType();
        var prop = type.GetProperty(propertyName, BindingFlags.Public | BindingFlags.NonPublic | BindingFlags.Instance);
        if (prop == null || prop.SetMethod == null)
            throw new InvalidOperationException($"Property '{propertyName}' not found or has no setter in '{type.Name}'");

        prop.SetValue(instance, value);
    }

    public Dictionary<string, object?> GetAllInstanceValues(object instance)
    {
        var result = new Dictionary<string, object?>();
        var type = instance.GetType();

        foreach (var field in type.GetFields(BindingFlags.Public | BindingFlags.NonPublic | BindingFlags.Instance))
        {
            try { result[$"field:{field.Name}"] = field.GetValue(instance); }
            catch { result[$"field:{field.Name}"] = "<error>"; }
        }

        foreach (var prop in type.GetProperties(BindingFlags.Public | BindingFlags.NonPublic | BindingFlags.Instance))
        {
            if (prop.GetMethod != null)
            {
                try { result[$"prop:{prop.Name}"] = prop.GetValue(instance); }
                catch { result[$"prop:{prop.Name}"] = "<error>"; }
            }
        }

        return result;
    }
}
