using System.Reflection;
using Mono.Cecil;
using Mono.Cecil.Cil;

namespace Lead.Hooks;

public class RuntimeHookManager
{
    private readonly MethodHookDispatcher _dispatcher;
    private readonly Dictionary<string, Assembly> _proxyAssemblies = new();
    private int _rewriteCount;

    public RuntimeHookManager(MethodHookDispatcher dispatcher)
    {
        _dispatcher = dispatcher;
        PreloadProxyAssemblies();
    }

    public int RewriteCount => _rewriteCount;

    public byte[] RewriteAssembly(string assemblyPath)
    {
        var readerParams = new ReaderParameters
        {
            ReadingMode = ReadingMode.Immediate,
            ReadWrite = false,
            InMemory = true
        };

        using var asm = AssemblyDefinition.ReadAssembly(assemblyPath, readerParams);
        var module = asm.MainModule;

        foreach (var type in module.GetTypes())
        {
            foreach (var method in type.Methods)
            {
                if (method.Body != null)
                    RewriteMethod(method, module);
            }
        }

        using var ms = new MemoryStream();
        asm.Write(ms);
        return ms.ToArray();
    }

    public byte[] RewriteAssembly(byte[] assemblyBytes)
    {
        using var input = new MemoryStream(assemblyBytes);
        var readerParams = new ReaderParameters
        {
            ReadingMode = ReadingMode.Immediate,
            ReadWrite = false,
            InMemory = true
        };

        using var asm = AssemblyDefinition.ReadAssembly(input, readerParams);
        var module = asm.MainModule;

        foreach (var type in module.GetTypes())
        {
            foreach (var method in type.Methods)
            {
                if (method.Body != null)
                    RewriteMethod(method, module);
            }
        }

        using var ms = new MemoryStream();
        asm.Write(ms);
        return ms.ToArray();
    }

    private void RewriteMethod(MethodDefinition method, ModuleDefinition module)
    {
        var il = method.Body.GetILProcessor();
        var instructions = method.Body.Instructions.ToList();

        for (int i = 0; i < instructions.Count; i++)
        {
            var instr = instructions[i];

            if (instr.OpCode != OpCodes.Call && instr.OpCode != OpCodes.Callvirt)
                continue;

            if (instr.Operand is not MethodReference target)
                continue;

            var rule = _dispatcher.FindRule(target.DeclaringType?.FullName ?? "", target.Name);
            if (rule == null)
                continue;

            var proxyRef = ResolveProxyMethod(rule, module, target);
            if (proxyRef == null)
                continue;

            var newCall = il.Create(OpCodes.Call, proxyRef);
            il.Replace(instr, newCall);
            _rewriteCount++;
        }
    }

    private MethodReference? ResolveProxyMethod(MethodHookRule rule, ModuleDefinition targetModule, MethodReference originalCall)
    {
        if (!_proxyAssemblies.TryGetValue(rule.ProxyType.Assembly.FullName!, out var proxyAsm))
            return null;

        var proxyType = proxyAsm.GetType(rule.ProxyType.FullName!);
        if (proxyType == null)
            return null;

        var proxyMethodInfo = proxyType.GetMethod(rule.ProxyMethod,
            BindingFlags.Public | BindingFlags.NonPublic | BindingFlags.Static);
        if (proxyMethodInfo == null)
            return null;

        var asmRef = targetModule.AssemblyReferences.FirstOrDefault(a => a.FullName == proxyAsm.FullName);
        if (asmRef == null)
        {
            asmRef = new AssemblyNameReference(proxyAsm.GetName().Name, proxyAsm.GetName().Version);
            targetModule.AssemblyReferences.Add(asmRef);
        }

        var typeRef = new TypeReference(proxyType.Namespace, proxyType.Name, targetModule, asmRef);

        var paramTypes = proxyMethodInfo.GetParameters()
            .Select(p => ImportType(p.ParameterType, targetModule, asmRef))
            .ToList();

        var returnType = ImportType(proxyMethodInfo.ReturnType, targetModule, asmRef);

        var methodRef = new MethodReference(rule.ProxyMethod, returnType, typeRef);
        foreach (var param in paramTypes)
            methodRef.Parameters.Add(new ParameterDefinition(param));

        return methodRef;
    }

    private TypeReference ImportType(Type type, ModuleDefinition module, AssemblyNameReference asmRef)
    {
        if (type == typeof(void)) return module.TypeSystem.Void;
        if (type == typeof(string)) return module.TypeSystem.String;
        if (type == typeof(int)) return module.TypeSystem.Int32;
        if (type == typeof(bool)) return module.TypeSystem.Boolean;
        if (type == typeof(long)) return module.TypeSystem.Int64;
        if (type == typeof(byte)) return module.TypeSystem.Byte;
        if (type == typeof(byte[])) return new ArrayType(module.TypeSystem.Byte);
        if (type == typeof(object)) return module.TypeSystem.Object;

        if (type.IsGenericType)
        {
            var genericDef = type.GetGenericTypeDefinition();
            var elemRef = new TypeReference(genericDef.Namespace, genericDef.Name, module, asmRef);
            var genInst = new GenericInstanceType(elemRef);
            foreach (var arg in type.GetGenericArguments())
                genInst.GenericArguments.Add(ImportType(arg, module, asmRef));
            return genInst;
        }

        return new TypeReference(type.Namespace, type.Name, module, asmRef);
    }

    private void PreloadProxyAssemblies()
    {
        foreach (var rule in _dispatcher.GetAllRules())
        {
            var asmName = rule.ProxyType.Assembly.FullName!;
            if (!_proxyAssemblies.ContainsKey(asmName))
                _proxyAssemblies[asmName] = rule.ProxyType.Assembly;
        }
    }
}
