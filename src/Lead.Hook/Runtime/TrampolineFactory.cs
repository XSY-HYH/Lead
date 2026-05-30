using System.Reflection;
using System.Runtime.InteropServices;

namespace Lead.Hook.Runtime;

public sealed class RuntimeHookContext
{
    public MethodInfo OriginalMethod { get; }
    public MethodInfo ReplacementMethod { get; }
    public object? Instance { get; }
    public object?[] Arguments { get; }
    public object? ReturnValue { get; set; }
    public bool SkipOriginal { get; set; }

    internal RuntimeHookContext(MethodInfo original, MethodInfo replacement, object? instance, object?[] arguments)
    {
        OriginalMethod = original;
        ReplacementMethod = replacement;
        Instance = instance;
        Arguments = arguments;
        SkipOriginal = false;
    }
}

public delegate object? RuntimeHookCallback(RuntimeHookContext context);

internal sealed class TrampolineFactory
{
    private static readonly Dictionary<MethodInfo, Delegate> _trampolines = new();

    public static Delegate CreateTrampoline(MethodInfo original, byte[] originalBytes, IntPtr originalEntry)
    {
        if (_trampolines.TryGetValue(original, out var existing))
            return existing;

        var trampoline = BuildTrampoline(original, originalBytes, originalEntry);
        _trampolines[original] = trampoline;
        return trampoline;
    }

    private static Delegate BuildTrampoline(MethodInfo original, byte[] originalBytes, IntPtr originalEntry)
    {
        var paramTypes = original.GetParameters().Select(p => p.ParameterType).ToArray();
        var delegateType = BuildDelegateType(paramTypes, original.ReturnType);

        var trampolineBytes = new byte[originalBytes.Length + 14];
        Array.Copy(originalBytes, 0, trampolineBytes, 0, originalBytes.Length);

        var trampolinePtr = Marshal.AllocHGlobal(trampolineBytes.Length);
        try
        {
            NativeMemory.MakeWritable(trampolinePtr, trampolineBytes.Length);
            Marshal.Copy(trampolineBytes, 0, trampolinePtr, originalBytes.Length);

            var jumpTarget = (long)originalEntry + originalBytes.Length;
            var jumpOffset = jumpTarget - ((long)trampolinePtr + originalBytes.Length + 14);

            trampolineBytes[originalBytes.Length] = 0xFF;
            trampolineBytes[originalBytes.Length + 1] = 0x25;
            trampolineBytes[originalBytes.Length + 2] = 0x00;
            trampolineBytes[originalBytes.Length + 3] = 0x00;
            trampolineBytes[originalBytes.Length + 4] = 0x00;
            trampolineBytes[originalBytes.Length + 5] = 0x00;
            BitConverter.TryWriteBytes(trampolineBytes.AsSpan(originalBytes.Length + 6, 8), jumpTarget);

            Marshal.Copy(trampolineBytes, originalBytes.Length, trampolinePtr + originalBytes.Length, 14);
        }
        catch
        {
            Marshal.FreeHGlobal(trampolinePtr);
            throw;
        }

        return Marshal.GetDelegateForFunctionPointer(trampolinePtr, delegateType);
    }

    private static Type BuildDelegateType(Type[] paramTypes, Type returnType)
    {
        var typeArgs = new List<Type>();
        typeArgs.AddRange(paramTypes);
        typeArgs.Add(returnType);

        if (typeArgs.Count == 1 && typeArgs[0] == typeof(void))
            return typeof(Action);

        if (returnType == typeof(void))
        {
            return paramTypes.Length switch
            {
                0 => typeof(Action),
                1 => typeof(Action<>).MakeGenericType(paramTypes),
                2 => typeof(Action<,>).MakeGenericType(paramTypes),
                3 => typeof(Action<,,>).MakeGenericType(paramTypes),
                4 => typeof(Action<,,,>).MakeGenericType(paramTypes),
                _ => throw new NotSupportedException($"Action with {paramTypes.Length} parameters is not supported")
            };
        }

        var funcArgs = paramTypes.Concat(new[] { returnType }).ToArray();
        return typeof(Func<,,,,,,,>).Assembly.GetType($"System.Func`{funcArgs.Length}")?
            .MakeGenericType(funcArgs)
            ?? throw new NotSupportedException($"Func with {funcArgs.Length} type arguments is not supported");
    }
}
