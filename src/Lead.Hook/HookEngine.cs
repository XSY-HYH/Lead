using System.Reflection;
using Mono.Cecil;
using Mono.Cecil.Cil;

namespace Lead.Hook;

public sealed class HookEngine
{
    private readonly List<HookRule> _rules = new();
    private readonly Dictionary<string, Assembly> _replacementAssemblies = new();
    private int _rewriteCount;
    private bool _sealed;

    public int RewriteCount => _rewriteCount;
    public IReadOnlyList<HookRule> Rules => _rules.AsReadOnly();

    public HookEngine AddRule(HookRule rule)
    {
        EnsureNotSealed();
        _rules.Add(rule ?? throw new ArgumentNullException(nameof(rule)));
        return this;
    }

    public HookEngine AddRules(IEnumerable<HookRule> rules)
    {
        EnsureNotSealed();
        _rules.AddRange(rules);
        return this;
    }

    public HookEngine AddRule(string originalType, string originalMethod, Type replacementType, string replacementMethod, HookType hookType = HookType.CallSite, string? description = null)
    {
        return AddRule(new HookRule(originalType, originalMethod, replacementType, replacementMethod, hookType, description));
    }

    public HookEngine RemoveRule(string originalType, string originalMethod)
    {
        EnsureNotSealed();
        _rules.RemoveAll(r => r.OriginalType == originalType && r.OriginalMethod == originalMethod);
        return this;
    }

    public HookEngine ClearRules()
    {
        EnsureNotSealed();
        _rules.Clear();
        return this;
    }

    public byte[] Rewrite(string assemblyPath)
    {
        Seal();
        var readerParams = new ReaderParameters
        {
            ReadingMode = ReadingMode.Immediate,
            ReadWrite = false,
            InMemory = true
        };

        using var asm = AssemblyDefinition.ReadAssembly(assemblyPath, readerParams);
        RewriteAssembly(asm);

        using var ms = new MemoryStream();
        asm.Write(ms);
        return ms.ToArray();
    }

    public byte[] Rewrite(byte[] assemblyBytes)
    {
        Seal();
        using var input = new MemoryStream(assemblyBytes);
        var readerParams = new ReaderParameters
        {
            ReadingMode = ReadingMode.Immediate,
            ReadWrite = false,
            InMemory = true
        };

        using var asm = AssemblyDefinition.ReadAssembly(input, readerParams);
        RewriteAssembly(asm);

        using var ms = new MemoryStream();
        asm.Write(ms);
        return ms.ToArray();
    }

    public HookResult RewriteWithResult(string assemblyPath)
    {
        var countBefore = _rewriteCount;
        var bytes = Rewrite(assemblyPath);
        return new HookResult(bytes, _rewriteCount - countBefore, _rules.Count);
    }

    public HookResult RewriteWithResult(byte[] assemblyBytes)
    {
        var countBefore = _rewriteCount;
        var bytes = Rewrite(assemblyBytes);
        return new HookResult(bytes, _rewriteCount - countBefore, _rules.Count);
    }

    private void Seal()
    {
        if (_sealed) return;
        _sealed = true;
        PreloadReplacementAssemblies();
    }

    private void EnsureNotSealed()
    {
        if (_sealed)
            throw new InvalidOperationException("Cannot modify rules after the engine has been used for rewriting. Create a new HookEngine instance.");
    }

    private void PreloadReplacementAssemblies()
    {
        foreach (var rule in _rules)
        {
            var asmName = rule.ReplacementType.Assembly.FullName!;
            if (!_replacementAssemblies.ContainsKey(asmName))
                _replacementAssemblies[asmName] = rule.ReplacementType.Assembly;
        }
    }

    private class RuleSet
    {
        public Dictionary<string, List<HookRule>> CallSite = new();
        public Dictionary<string, List<HookRule>> MethodBody = new();
        public Dictionary<string, List<HookRule>> NewObj = new();
        public Dictionary<string, List<HookRule>> FieldRead = new();
        public Dictionary<string, List<HookRule>> FieldWrite = new();
        public Dictionary<string, List<HookRule>> TypeCheck = new();
        public Dictionary<string, List<HookRule>> Box = new();
        public Dictionary<string, List<HookRule>> FunctionPointer = new();
    }

    private RuleSet BuildRuleSet()
    {
        var rs = new RuleSet();
        foreach (var rule in _rules)
        {
            var key = $"{rule.OriginalType}::{rule.OriginalMethod}";
            var target = rule.HookType switch
            {
                HookType.CallSite => rs.CallSite,
                HookType.MethodBody => rs.MethodBody,
                HookType.NewObj => rs.NewObj,
                HookType.FieldRead => rs.FieldRead,
                HookType.FieldWrite => rs.FieldWrite,
                HookType.TypeCheck => rs.TypeCheck,
                HookType.Box => rs.Box,
                HookType.FunctionPointer => rs.FunctionPointer,
                _ => rs.CallSite
            };
            if (!target.ContainsKey(key))
                target[key] = new List<HookRule>();
            target[key].Add(rule);
        }
        return rs;
    }

    private void RewriteAssembly(AssemblyDefinition asm)
    {
        var module = asm.MainModule;
        var rs = BuildRuleSet();

        foreach (var type in module.GetTypes())
        {
            foreach (var method in type.Methods)
            {
                var methodKey = $"{type.FullName}::{method.Name}";
                if (rs.MethodBody.TryGetValue(methodKey, out var bodyRules) && bodyRules.Count > 0)
                    ReplaceMethodBody(method, module, bodyRules[0]);
            }

            foreach (var method in type.Methods)
            {
                if (method.Body != null)
                    RewriteInstructions(method, module, rs);
            }
        }
    }

    private void ReplaceMethodBody(MethodDefinition method, ModuleDefinition module, HookRule rule)
    {
        if (method.Body == null) return;

        var il = method.Body.GetILProcessor();

        while (method.Body.Instructions.Count > 0)
            il.Remove(method.Body.Instructions[0]);

        method.Body.ExceptionHandlers.Clear();
        method.Body.Variables.Clear();

        int paramCount = method.HasThis ? method.Parameters.Count + 1 : method.Parameters.Count;
        for (int i = 0; i < paramCount; i++)
            il.Append(il.Create(GetLdarg(i)));

        var replacementRef = ResolveMethodBodyReplacement(rule, module, method);
        if (replacementRef == null)
            return;

        il.Append(il.Create(OpCodes.Call, replacementRef));
        il.Append(il.Create(OpCodes.Ret));

        _rewriteCount++;
    }

    private void RewriteInstructions(MethodDefinition method, ModuleDefinition module, RuleSet rs)
    {
        var il = method.Body.GetILProcessor();
        var instructions = method.Body.Instructions.ToList();

        for (int i = 0; i < instructions.Count; i++)
        {
            var instr = instructions[i];
            var handled = false;

            if (!handled && (instr.OpCode == OpCodes.Call || instr.OpCode == OpCodes.Callvirt))
                handled = TryRewriteCallSite(instr, il, module, rs.CallSite);

            if (!handled && instr.OpCode == OpCodes.Newobj)
                handled = TryRewriteNewObj(instr, il, module, rs.NewObj);

            if (!handled && (instr.OpCode == OpCodes.Ldfld || instr.OpCode == OpCodes.Ldsfld))
                handled = TryRewriteFieldRead(instr, il, module, rs.FieldRead);

            if (!handled && (instr.OpCode == OpCodes.Stfld || instr.OpCode == OpCodes.Stsfld))
                handled = TryRewriteFieldWrite(instr, il, module, rs.FieldWrite);

            if (!handled && (instr.OpCode == OpCodes.Isinst || instr.OpCode == OpCodes.Castclass))
                handled = TryRewriteTypeCheck(instr, il, module, rs.TypeCheck);

            if (!handled && (instr.OpCode == OpCodes.Box || instr.OpCode == OpCodes.Unbox_Any))
                handled = TryRewriteBox(instr, il, module, rs.Box);

            if (!handled && (instr.OpCode == OpCodes.Ldftn || instr.OpCode == OpCodes.Ldvirtftn))
                handled = TryRewriteFunctionPointer(instr, il, module, rs.FunctionPointer);

            if (handled)
                _rewriteCount++;
        }
    }

    private bool TryRewriteCallSite(Instruction instr, ILProcessor il, ModuleDefinition module, Dictionary<string, List<HookRule>> rules)
    {
        if (instr.Operand is not MethodReference target)
            return false;

        var key = $"{target.DeclaringType?.FullName}::{target.Name}";
        if (!rules.TryGetValue(key, out var ruleList) || ruleList.Count == 0)
            return false;

        var rule = ruleList[0];
        var isInstanceCall = instr.OpCode == OpCodes.Callvirt && target.HasThis;
        var replacementRef = ResolveCallSiteReplacement(rule, module, target, isInstanceCall);
        if (replacementRef == null)
            return false;

        var expectedParamCount = isInstanceCall ? target.Parameters.Count + 1 : target.Parameters.Count;
        if (replacementRef.Parameters.Count != expectedParamCount)
            return false;

        var newCall = il.Create(OpCodes.Call, replacementRef);
        il.Replace(instr, newCall);
        return true;
    }

    private bool TryRewriteNewObj(Instruction instr, ILProcessor il, ModuleDefinition module, Dictionary<string, List<HookRule>> rules)
    {
        if (instr.Operand is not MethodReference ctor)
            return false;

        var key = $"{ctor.DeclaringType?.FullName}::.ctor";
        if (!rules.TryGetValue(key, out var ruleList) || ruleList.Count == 0)
            return false;

        var rule = ruleList[0];
        var replacementRef = ResolveNewObjReplacement(rule, module, ctor);
        if (replacementRef == null)
            return false;

        if (ctor.Parameters.Count != replacementRef.Parameters.Count)
            return false;

        var newCall = il.Create(OpCodes.Call, replacementRef);
        il.Replace(instr, newCall);
        return true;
    }

    private bool TryRewriteFieldRead(Instruction instr, ILProcessor il, ModuleDefinition module, Dictionary<string, List<HookRule>> rules)
    {
        if (instr.Operand is not FieldReference field)
            return false;

        var key = $"{field.DeclaringType?.FullName}::{field.Name}";
        if (!rules.TryGetValue(key, out var ruleList) || ruleList.Count == 0)
            return false;

        var rule = ruleList[0];
        var isStatic = instr.OpCode == OpCodes.Ldsfld;
        var replacementRef = ResolveFieldReplacement(rule, module, isStatic ? 0 : 1);
        if (replacementRef == null)
            return false;

        var expectedParamCount = isStatic ? 0 : 1;
        if (replacementRef.Parameters.Count != expectedParamCount)
            return false;

        var newCall = il.Create(OpCodes.Call, replacementRef);
        il.Replace(instr, newCall);
        return true;
    }

    private bool TryRewriteFieldWrite(Instruction instr, ILProcessor il, ModuleDefinition module, Dictionary<string, List<HookRule>> rules)
    {
        if (instr.Operand is not FieldReference field)
            return false;

        var key = $"{field.DeclaringType?.FullName}::{field.Name}";
        if (!rules.TryGetValue(key, out var ruleList) || ruleList.Count == 0)
            return false;

        var rule = ruleList[0];
        var isStatic = instr.OpCode == OpCodes.Stsfld;
        var replacementRef = ResolveFieldReplacement(rule, module, isStatic ? 1 : 2);
        if (replacementRef == null)
            return false;

        var expectedParamCount = isStatic ? 1 : 2;
        if (replacementRef.Parameters.Count != expectedParamCount)
            return false;

        var newCall = il.Create(OpCodes.Call, replacementRef);
        il.Replace(instr, newCall);
        return true;
    }

    private bool TryRewriteTypeCheck(Instruction instr, ILProcessor il, ModuleDefinition module, Dictionary<string, List<HookRule>> rules)
    {
        if (instr.Operand is not TypeReference typeRef)
            return false;

        var key = $"{typeRef.FullName}::check";
        if (!rules.TryGetValue(key, out var ruleList) || ruleList.Count == 0)
            return false;

        var rule = ruleList[0];
        var replacementRef = ResolveTypeCheckReplacement(rule, module);
        if (replacementRef == null)
            return false;

        if (replacementRef.Parameters.Count != 1)
            return false;

        var newCall = il.Create(OpCodes.Call, replacementRef);
        il.Replace(instr, newCall);
        return true;
    }

    private bool TryRewriteBox(Instruction instr, ILProcessor il, ModuleDefinition module, Dictionary<string, List<HookRule>> rules)
    {
        if (instr.Operand is not TypeReference typeRef)
            return false;

        var key = $"{typeRef.FullName}::{(instr.OpCode == OpCodes.Box ? "box" : "unbox")}";
        if (!rules.TryGetValue(key, out var ruleList) || ruleList.Count == 0)
            return false;

        var rule = ruleList[0];
        var replacementRef = ResolveBoxReplacement(rule, module);
        if (replacementRef == null)
            return false;

        if (replacementRef.Parameters.Count != 1)
            return false;

        var newCall = il.Create(OpCodes.Call, replacementRef);
        il.Replace(instr, newCall);
        return true;
    }

    private bool TryRewriteFunctionPointer(Instruction instr, ILProcessor il, ModuleDefinition module, Dictionary<string, List<HookRule>> rules)
    {
        if (instr.Operand is not MethodReference target)
            return false;

        var key = $"{target.DeclaringType?.FullName}::{target.Name}";
        if (!rules.TryGetValue(key, out var ruleList) || ruleList.Count == 0)
            return false;

        var rule = ruleList[0];
        var isVirtual = instr.OpCode == OpCodes.Ldvirtftn;
        var replacementRef = ResolveFuncPtrReplacement(rule, module, isVirtual);
        if (replacementRef == null)
            return false;

        var expectedParamCount = isVirtual ? 1 : 0;
        if (replacementRef.Parameters.Count != expectedParamCount)
            return false;

        var newCall = il.Create(OpCodes.Call, replacementRef);
        il.Replace(instr, newCall);
        return true;
    }

    private MethodReference? ResolveCallSiteReplacement(HookRule rule, ModuleDefinition targetModule, MethodReference originalCall, bool isInstanceCall)
    {
        if (!_replacementAssemblies.TryGetValue(rule.ReplacementType.Assembly.FullName!, out var replacementAsm))
            return null;

        var replacementType = replacementAsm.GetType(rule.ReplacementType.FullName!);
        if (replacementType == null)
            return null;

        var expectedParamCount = isInstanceCall ? originalCall.Parameters.Count + 1 : originalCall.Parameters.Count;
        var replacementMethodInfo = FindReplacementMethod(replacementType, rule.ReplacementMethod, expectedParamCount);
        if (replacementMethodInfo == null)
            return null;

        return BuildMethodReference(replacementMethodInfo, rule.ReplacementMethod, replacementType, replacementAsm, targetModule);
    }

    private MethodReference? ResolveMethodBodyReplacement(HookRule rule, ModuleDefinition targetModule, MethodDefinition originalMethod)
    {
        if (!_replacementAssemblies.TryGetValue(rule.ReplacementType.Assembly.FullName!, out var replacementAsm))
            return null;

        var replacementType = replacementAsm.GetType(rule.ReplacementType.FullName!);
        if (replacementType == null)
            return null;

        var expectedParamCount = originalMethod.HasThis ? originalMethod.Parameters.Count + 1 : originalMethod.Parameters.Count;
        var replacementMethodInfo = FindReplacementMethod(replacementType, rule.ReplacementMethod, expectedParamCount);
        if (replacementMethodInfo == null)
            return null;

        return BuildMethodReference(replacementMethodInfo, rule.ReplacementMethod, replacementType, replacementAsm, targetModule);
    }

    private MethodReference? ResolveNewObjReplacement(HookRule rule, ModuleDefinition targetModule, MethodReference originalCtor)
    {
        if (!_replacementAssemblies.TryGetValue(rule.ReplacementType.Assembly.FullName!, out var replacementAsm))
            return null;

        var replacementType = replacementAsm.GetType(rule.ReplacementType.FullName!);
        if (replacementType == null)
            return null;

        var replacementMethodInfo = FindReplacementMethod(replacementType, rule.ReplacementMethod, originalCtor.Parameters.Count);
        if (replacementMethodInfo == null)
            return null;

        return BuildMethodReference(replacementMethodInfo, rule.ReplacementMethod, replacementType, replacementAsm, targetModule);
    }

    private MethodReference? ResolveFieldReplacement(HookRule rule, ModuleDefinition targetModule, int expectedParamCount)
    {
        if (!_replacementAssemblies.TryGetValue(rule.ReplacementType.Assembly.FullName!, out var replacementAsm))
            return null;

        var replacementType = replacementAsm.GetType(rule.ReplacementType.FullName!);
        if (replacementType == null)
            return null;

        var replacementMethodInfo = FindReplacementMethod(replacementType, rule.ReplacementMethod, expectedParamCount);
        if (replacementMethodInfo == null)
            return null;

        return BuildMethodReference(replacementMethodInfo, rule.ReplacementMethod, replacementType, replacementAsm, targetModule);
    }

    private MethodReference? ResolveTypeCheckReplacement(HookRule rule, ModuleDefinition targetModule)
    {
        if (!_replacementAssemblies.TryGetValue(rule.ReplacementType.Assembly.FullName!, out var replacementAsm))
            return null;

        var replacementType = replacementAsm.GetType(rule.ReplacementType.FullName!);
        if (replacementType == null)
            return null;

        var replacementMethodInfo = FindReplacementMethod(replacementType, rule.ReplacementMethod, 1);
        if (replacementMethodInfo == null)
            return null;

        return BuildMethodReference(replacementMethodInfo, rule.ReplacementMethod, replacementType, replacementAsm, targetModule);
    }

    private MethodReference? ResolveBoxReplacement(HookRule rule, ModuleDefinition targetModule)
    {
        if (!_replacementAssemblies.TryGetValue(rule.ReplacementType.Assembly.FullName!, out var replacementAsm))
            return null;

        var replacementType = replacementAsm.GetType(rule.ReplacementType.FullName!);
        if (replacementType == null)
            return null;

        var replacementMethodInfo = FindReplacementMethod(replacementType, rule.ReplacementMethod, 1);
        if (replacementMethodInfo == null)
            return null;

        return BuildMethodReference(replacementMethodInfo, rule.ReplacementMethod, replacementType, replacementAsm, targetModule);
    }

    private MethodReference? ResolveFuncPtrReplacement(HookRule rule, ModuleDefinition targetModule, bool isVirtual)
    {
        if (!_replacementAssemblies.TryGetValue(rule.ReplacementType.Assembly.FullName!, out var replacementAsm))
            return null;

        var replacementType = replacementAsm.GetType(rule.ReplacementType.FullName!);
        if (replacementType == null)
            return null;

        var expectedParamCount = isVirtual ? 1 : 0;
        var replacementMethodInfo = FindReplacementMethod(replacementType, rule.ReplacementMethod, expectedParamCount);
        if (replacementMethodInfo == null)
            return null;

        return BuildMethodReference(replacementMethodInfo, rule.ReplacementMethod, replacementType, replacementAsm, targetModule);
    }

    private MethodInfo? FindReplacementMethod(Type replacementType, string methodName, int expectedParamCount)
    {
        var result = replacementType.GetMethods(BindingFlags.Public | BindingFlags.NonPublic | BindingFlags.Static)
            .FirstOrDefault(m => m.Name == methodName && m.GetParameters().Length == expectedParamCount);
        if (result != null)
            return result;

        return replacementType.GetMethod(methodName, BindingFlags.Public | BindingFlags.NonPublic | BindingFlags.Static);
    }

    private MethodReference BuildMethodReference(MethodInfo replacementMethodInfo, string methodName, Type replacementType, Assembly replacementAsm, ModuleDefinition targetModule)
    {
        var asmRef = targetModule.AssemblyReferences.FirstOrDefault(a => a.FullName == replacementAsm.FullName);
        if (asmRef == null)
        {
            asmRef = new AssemblyNameReference(replacementAsm.GetName().Name, replacementAsm.GetName().Version);
            targetModule.AssemblyReferences.Add(asmRef);
        }

        var typeRef = new TypeReference(replacementType.Namespace, replacementType.Name, targetModule, asmRef);

        var paramTypes = replacementMethodInfo.GetParameters()
            .Select(p => ImportType(p.ParameterType, targetModule, asmRef))
            .ToList();

        var returnType = ImportType(replacementMethodInfo.ReturnType, targetModule, asmRef);

        var methodRef = new MethodReference(methodName, returnType, typeRef);
        foreach (var param in paramTypes)
            methodRef.Parameters.Add(new ParameterDefinition(param));

        return methodRef;
    }

    private static OpCode GetLdarg(int index)
    {
        return index switch
        {
            0 => OpCodes.Ldarg_0,
            1 => OpCodes.Ldarg_1,
            2 => OpCodes.Ldarg_2,
            3 => OpCodes.Ldarg_3,
            _ => OpCodes.Ldarg
        };
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
        if (type == typeof(double)) return module.TypeSystem.Double;
        if (type == typeof(float)) return module.TypeSystem.Single;
        if (type == typeof(char)) return module.TypeSystem.Char;
        if (type == typeof(short)) return module.TypeSystem.Int16;
        if (type == typeof(ushort)) return module.TypeSystem.UInt16;
        if (type == typeof(uint)) return module.TypeSystem.UInt32;
        if (type == typeof(ulong)) return module.TypeSystem.UInt64;
        if (type == typeof(IntPtr)) return module.TypeSystem.IntPtr;
        if (type == typeof(UIntPtr)) return module.TypeSystem.UIntPtr;

        try
        {
            var imported = module.ImportReference(type);
            return imported;
        }
        catch
        {
            if (type.IsGenericType)
            {
                var genericDef = type.GetGenericTypeDefinition();
                var elemRef = new TypeReference(genericDef.Namespace, genericDef.Name, module, asmRef);
                var genInst = new GenericInstanceType(elemRef);
                foreach (var arg in type.GetGenericArguments())
                    genInst.GenericArguments.Add(ImportType(arg, module, asmRef));
                return genInst;
            }

            if (type.IsArray)
            {
                var elementType = ImportType(type.GetElementType()!, module, asmRef);
                return new ArrayType(elementType);
            }

            return new TypeReference(type.Namespace, type.Name, module, asmRef);
        }
    }
}
