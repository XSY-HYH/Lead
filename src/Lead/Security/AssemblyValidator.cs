using Mono.Cecil;
using Mono.Cecil.Cil;

namespace Lead;

public class AssemblyValidator
{
    private readonly SecurityPolicy _policy;

    public AssemblyValidator() : this(new SecurityPolicy()) { }

    public AssemblyValidator(SecurityPolicy policy)
    {
        _policy = policy;
    }

    public ValidationResult Validate(string assemblyPath)
    {
        try
        {
            var readerParams = new ReaderParameters
            {
                AssemblyResolver = new DefaultAssemblyResolver(),
                ReadingMode = ReadingMode.Immediate,
                ReadWrite = false,
                InMemory = true
            };

            using var asm = AssemblyDefinition.ReadAssembly(assemblyPath, readerParams);
            var errors = new List<ValidationError>();
            var warnings = new List<ValidationWarning>();

            CheckAssemblyAttributes(asm, errors);

            foreach (var type in asm.MainModule.Types)
            {
                CheckType(type, errors, warnings);
                CheckNestedTypes(type, errors, warnings);
            }

            return new ValidationResult
            {
                IsValid = errors.Count == 0,
                Errors = errors,
                Warnings = warnings
            };
        }
        catch (Exception ex)
        {
            return ValidationResult.Error($"{ErrorCode.ScanFailed}: {ex.Message}");
        }
    }

    private void CheckNestedTypes(TypeDefinition type, List<ValidationError> errors, List<ValidationWarning> warnings)
    {
        foreach (var nested in type.NestedTypes)
        {
            CheckType(nested, errors, warnings);
            CheckNestedTypes(nested, errors, warnings);
        }
    }

    private void CheckType(TypeDefinition type, List<ValidationError> errors, List<ValidationWarning> warnings)
    {
        if (_policy.ForbiddenTypes.Contains(type.FullName))
        {
            errors.Add(new ValidationError(type.FullName, ErrorCode.ForbiddenType, Severity.Error));
        }

        foreach (var attr in type.CustomAttributes)
        {
            if (_policy.ForbiddenAttributes.Contains(attr.AttributeType.FullName))
            {
                errors.Add(new ValidationError(type.FullName, ErrorCode.ForbiddenAttribute, Severity.Error));
            }
        }

        foreach (var method in type.Methods)
            CheckMethod(method, type.FullName, errors, warnings);

        foreach (var field in type.Fields)
            CheckField(field, type.FullName, errors);

        foreach (var property in type.Properties)
        {
            if (property.GetMethod != null)
                CheckMethod(property.GetMethod, type.FullName, errors, warnings);
            if (property.SetMethod != null)
                CheckMethod(property.SetMethod, type.FullName, errors, warnings);
        }
    }

    private void CheckMethod(MethodDefinition method, string typeName,
                             List<ValidationError> errors, List<ValidationWarning> warnings)
    {
        if (method.Body != null && HasUnsafeInstructions(method.Body))
        {
            errors.Add(new ValidationError($"{typeName}.{method.Name}", ErrorCode.UnsafeCode, Severity.Error));
        }

        if (method.IsPInvokeImpl || method.PInvokeInfo != null)
        {
            errors.Add(new ValidationError($"{typeName}.{method.Name}", ErrorCode.PInvoke, Severity.Error));
        }

        foreach (var attr in method.CustomAttributes)
        {
            if (_policy.ForbiddenAttributes.Contains(attr.AttributeType.FullName))
            {
                errors.Add(new ValidationError($"{typeName}.{method.Name}", ErrorCode.ForbiddenAttribute, Severity.Error));
            }
        }

        if (method.ReturnType is PointerType)
        {
            errors.Add(new ValidationError($"{typeName}.{method.Name}", ErrorCode.PointerType, Severity.Error));
        }

        foreach (var param in method.Parameters)
        {
            if (param.ParameterType is PointerType)
            {
                errors.Add(new ValidationError($"{typeName}.{method.Name}", ErrorCode.PointerType, Severity.Error));
            }

            if (param.IsOut || param.ParameterType.IsByReference)
            {
                warnings.Add(new ValidationWarning($"{typeName}.{method.Name}", "OUT_REF_PARAM", Severity.Warning));
            }
        }

        if (method.Body != null)
            CheckILInstructions(method, typeName, errors, warnings);
    }

    private void CheckILInstructions(MethodDefinition method, string typeName,
                                      List<ValidationError> errors, List<ValidationWarning> warnings)
    {
        foreach (var instruction in method.Body.Instructions)
        {
            if (instruction.OpCode == OpCodes.Calli)
            {
                errors.Add(new ValidationError($"{typeName}.{method.Name}", ErrorCode.UnmanagedCall, Severity.Error));
                continue;
            }

            if (instruction.OpCode == OpCodes.Ldftn || instruction.OpCode == OpCodes.Ldvirtftn)
            {
                errors.Add(new ValidationError($"{typeName}.{method.Name}", ErrorCode.UnmanagedCall, Severity.Error));
                continue;
            }

            if (instruction.OpCode == OpCodes.Call ||
                instruction.OpCode == OpCodes.Callvirt)
            {
                if (instruction.Operand is not MethodReference target) continue;

                if (_policy.ForbiddenMethods.Contains(target.FullName))
                {
                    errors.Add(new ValidationError($"{typeName}.{method.Name}", ErrorCode.ForbiddenMethod, Severity.Error));
                }

                var shortName = target.DeclaringType != null ? $"{target.DeclaringType.FullName}.{target.Name}" : target.Name;
                if (_policy.ForbiddenMethods.Contains(shortName))
                {
                    errors.Add(new ValidationError($"{typeName}.{method.Name}", ErrorCode.ForbiddenMethod, Severity.Error));
                }

                if (target.DeclaringType != null && _policy.ForbiddenTypes.Contains(target.DeclaringType.FullName))
                {
                    errors.Add(new ValidationError($"{typeName}.{method.Name}", ErrorCode.ForbiddenType, Severity.Error));
                }

                if (target is MethodDefinition targetDef && targetDef.IsPInvokeImpl)
                {
                    errors.Add(new ValidationError($"{typeName}.{method.Name}", ErrorCode.PInvoke, Severity.Error));
                }
            }

            if (instruction.OpCode == OpCodes.Newobj)
            {
                if (instruction.Operand is MethodReference ctor && ctor.DeclaringType != null)
                {
                    if (_policy.ForbiddenTypes.Contains(ctor.DeclaringType.FullName))
                    {
                        errors.Add(new ValidationError($"{typeName}.{method.Name}", ErrorCode.ForbiddenType, Severity.Error));
                    }

                    var ctorShortName = $"{ctor.DeclaringType.FullName}.{ctor.Name}";
                    if (_policy.ForbiddenMethods.Contains(ctorShortName))
                    {
                        errors.Add(new ValidationError($"{typeName}.{method.Name}", ErrorCode.ForbiddenMethod, Severity.Error));
                    }
                }
            }

            if (instruction.OpCode == OpCodes.Ldtoken)
            {
                warnings.Add(new ValidationWarning($"{typeName}.{method.Name}", "LDTOKEN_REFLECTION", Severity.Warning));
            }
        }
    }

    private void CheckField(FieldDefinition field, string typeName, List<ValidationError> errors)
    {
        if (field.FieldType is PointerType)
        {
            errors.Add(new ValidationError($"{typeName}.{field.Name}", ErrorCode.PointerType, Severity.Error));
        }

        if (_policy.ForbiddenTypes.Contains(field.FieldType.FullName))
        {
            errors.Add(new ValidationError($"{typeName}.{field.Name}", ErrorCode.ForbiddenType, Severity.Error));
        }

        foreach (var attr in field.CustomAttributes)
        {
            if (_policy.ForbiddenAttributes.Contains(attr.AttributeType.FullName))
            {
                errors.Add(new ValidationError($"{typeName}.{field.Name}", ErrorCode.ForbiddenAttribute, Severity.Error));
            }
        }
    }

    private void CheckAssemblyAttributes(AssemblyDefinition asm, List<ValidationError> errors)
    {
        foreach (var attr in asm.CustomAttributes)
        {
            if (_policy.ForbiddenAttributes.Contains(attr.AttributeType.FullName))
            {
                errors.Add(new ValidationError("Assembly", ErrorCode.ForbiddenAttribute, Severity.Error));
            }
        }
    }

    private static bool HasUnsafeInstructions(Mono.Cecil.Cil.MethodBody body)
    {
        foreach (var variable in body.Variables)
        {
            if (variable.VariableType is PointerType || variable.VariableType.IsByReference)
                return true;
        }

        foreach (var instruction in body.Instructions)
        {
            if (instruction.OpCode == OpCodes.Conv_U ||
                instruction.OpCode == OpCodes.Conv_I ||
                instruction.OpCode == OpCodes.Conv_U8 ||
                instruction.OpCode == OpCodes.Conv_I8 ||
                instruction.OpCode == OpCodes.Ldind_I ||
                instruction.OpCode == OpCodes.Stind_I ||
                instruction.OpCode == OpCodes.Initblk ||
                instruction.OpCode == OpCodes.Cpblk)
            {
                return true;
            }
        }

        return false;
    }
}
