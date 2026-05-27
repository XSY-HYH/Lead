namespace Lead;

public class SecurityPolicy
{
    public HashSet<string> ForbiddenTypes { get; } = new(DefaultForbiddenTypes);
    public HashSet<string> ForbiddenMethods { get; } = new(DefaultForbiddenMethods);
    public HashSet<string> ForbiddenAttributes { get; } = new(DefaultForbiddenAttributes);
    public HashSet<string> BlockedAssemblyPrefixes { get; } = new(DefaultBlockedAssemblyPrefixes);

    private static readonly string[] DefaultForbiddenTypes =
    {
        "System.Runtime.InteropServices.Marshal",
        "System.Runtime.InteropServices.MemoryMarshal",
        "System.Runtime.InteropServices.MarshalAsAttribute",
        "System.Runtime.InteropServices.StructLayoutAttribute",
        "System.Runtime.InteropServices.FieldOffsetAttribute",
        "System.Runtime.InteropServices.GCHandle",
        "System.Runtime.CompilerServices.Unsafe",
        "System.Buffers.MemoryHandle",
        "System.IntPtr",
        "System.UIntPtr",
        "System.Span`1",
        "System.ReadOnlySpan`1",
        "System.Buffer",
        "System.Runtime.InteropServices.SequenceLayout",
        "System.Reflection.Emit.AssemblyBuilder",
        "System.Reflection.Emit.ModuleBuilder",
        "System.Reflection.Emit.TypeBuilder",
        "System.Reflection.Emit.MethodBuilder",
        "System.Reflection.Emit.DynamicMethod",
        "System.Reflection.Emit.ILGenerator",
        "System.Diagnostics.Process",
        "System.Diagnostics.ProcessStartInfo",
        "System.Diagnostics.ProcessThread",
        "System.Diagnostics.ProcessModule",
        "System.Environment",
        "System.AppDomain",
        "System.AppDomainSetup",
        "System.Runtime.InteropServices.NativeLibrary",
        "System.Runtime.InteropServices.DllImportAttribute",
        "System.Reflection.Assembly",
        "System.Reflection.Module",
        "System.Reflection.Emit",
        "System.Reflection.MethodBody",
        "System.Reflection.LocalVariableInfo",
        "System.Security.Cryptography.SymmetricAlgorithm",
        "System.Security.Cryptography.AsymmetricAlgorithm",
        "System.Security.Cryptography.HashAlgorithm",
        "System.Security.Cryptography.RandomNumberGenerator",
        "System.Threading.Thread",
        "System.Threading.ThreadPool",
        "System.Threading.Tasks.Parallel",
        "System.Threading.Semaphore",
        "System.Threading.Mutex",
        "System.Threading.ReaderWriterLockSlim",
        "System.Threading.Monitor"
    };

    private static readonly string[] DefaultForbiddenMethods =
    {
        "System.GC.AllocateArray",
        "System.GC.AllocateUninitializedArray",
        "System.Buffer.MemoryCopy",
        "System.Buffer.BlockCopy",
        "System.Runtime.CompilerServices.RuntimeHelpers.AllocateTypeAssociatedMemory",
        "System.Type.InvokeMember",
        "System.Reflection.MethodInfo.Invoke",
        "System.Reflection.FieldInfo.SetValue",
        "System.Reflection.FieldInfo.GetValue",
        "System.Reflection.PropertyInfo.SetValue",
        "System.Reflection.PropertyInfo.GetValue",
        "System.Activator.CreateInstance",
        "System.Runtime.Serialization.FormatterServices.GetUninitializedObject",
        "System.AppDomain.Load",
        "System.Runtime.Loader.AssemblyLoadContext.LoadFromAssemblyPath",
        "System.Reflection.Assembly.Load",
        "System.Reflection.Assembly.LoadFile",
        "System.Reflection.Assembly.LoadFrom",
        "System.Reflection.Assembly.UnsafeLoadFrom",
        "System.Runtime.Serialization.FormatterServices.GetSafeUninitializedObject",
        "System.Runtime.Serialization.FormatterServices.PopulateObjectMembers",
        "System.WeakReference`1..ctor",
        "System.WeakReference..ctor",
        "System.Runtime.CompilerServices.GCHandle.Alloc",
        "System.Runtime.CompilerServices.GCHandle.FromIntPtr",
        "System.Threading.Tasks.Task.Run",
        "System.Threading.Tasks.Task.Factory.StartNew",
        "System.Threading.Tasks.TaskCompletionSource`1.SetResult",
        "System.Threading.Tasks.TaskCompletionSource`1.SetException",
        "System.Runtime.InteropServices.MemoryMarshal.Cast",
        "System.Runtime.InteropServices.MemoryMarshal.AsBytes",
        "System.Runtime.InteropServices.MemoryMarshal.GetReference",
        "System.Runtime.InteropServices.MemoryMarshal.Read",
        "System.Runtime.InteropServices.MemoryMarshal.Write",
        "System.Runtime.InteropServices.MemoryMarshal.CreateSpan",
        "System.Runtime.InteropServices.MemoryMarshal.CreateReadOnlySpan"
    };

    private static readonly string[] DefaultForbiddenAttributes =
    {
        "System.Runtime.InteropServices.DllImportAttribute",
        "System.Runtime.InteropServices.UnmanagedFunctionPointerAttribute",
        "System.Runtime.InteropServices.SuppressGCTransitionAttribute",
        "System.Runtime.InteropServices.StructLayoutAttribute",
        "System.Runtime.InteropServices.FieldOffsetAttribute",
        "System.Runtime.InteropServices.UnmanagedCallersOnlyAttribute",
        "System.Security.SuppressUnmanagedCodeSecurityAttribute",
        "System.Runtime.CompilerServices.UnsafeValueTypeAttribute",
        "System.Runtime.CompilerServices.MethodImplAttribute",
        "System.Runtime.Versioning.SupportedOSPlatformAttribute",
        "System.Security.SecurityCriticalAttribute",
        "System.Security.SecuritySafeCriticalAttribute"
    };

    private static readonly string[] DefaultBlockedAssemblyPrefixes =
    {
        "System.Diagnostics.Process",
        "System.Reflection.Emit",
        "System.Runtime.InteropServices",
        "Microsoft.Win32.Registry",
        "System.Security.Permissions",
        "System.Net.HttpListener",
        "System.Net.Sockets",
        "System.IO.Pipes"
    };
}
