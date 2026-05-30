using System.Reflection;
using System.Runtime.InteropServices;

namespace Lead.Hooks.Proxies;

public static class NativeInteropProxy
{
    internal static RedirectMode Mode { get; set; } = RedirectMode.Honeypot;

    private static readonly List<string> AccessLog = new();

    public static IntPtr Load(string libraryPath)
    {
        RecordAccess($"NATIVELIB_LOAD({libraryPath})");
        switch (Mode)
        {
            case RedirectMode.Block:
                throw new SandboxException(ErrorCode.ForbiddenType);
            case RedirectMode.Honeypot:
                return IntPtr.Zero;
            default:
                return IntPtr.Zero;
        }
    }

    public static IntPtr Load(string libraryPath, Assembly assembly, Nullable<DllImportSearchPath> searchPath)
    {
        RecordAccess($"NATIVELIB_LOAD({libraryPath}, {assembly?.FullName})");
        switch (Mode)
        {
            case RedirectMode.Block:
                throw new SandboxException(ErrorCode.ForbiddenType);
            case RedirectMode.Honeypot:
                return IntPtr.Zero;
            default:
                return IntPtr.Zero;
        }
    }

    public static IntPtr GetExport(IntPtr handle, string name)
    {
        RecordAccess($"NATIVELIB_GETEXPORT(handle=0x{handle.ToInt64():X}, {name})");
        switch (Mode)
        {
            case RedirectMode.Block:
                throw new SandboxException(ErrorCode.ForbiddenType);
            case RedirectMode.Honeypot:
                return IntPtr.Zero;
            default:
                return IntPtr.Zero;
        }
    }

    public static void Free(IntPtr handle)
    {
        RecordAccess($"NATIVELIB_FREE(handle=0x{handle.ToInt64():X})");
        switch (Mode)
        {
            case RedirectMode.Block:
                throw new SandboxException(ErrorCode.ForbiddenType);
            case RedirectMode.Honeypot:
                break;
        }
    }

    public static bool TryLoad(string libraryPath, out IntPtr handle)
    {
        RecordAccess($"NATIVELIB_TRYLOAD({libraryPath})");
        switch (Mode)
        {
            case RedirectMode.Block:
                throw new SandboxException(ErrorCode.ForbiddenType);
            case RedirectMode.Honeypot:
                handle = IntPtr.Zero;
                return false;
            default:
                handle = IntPtr.Zero;
                return false;
        }
    }

    public static bool TryLoad(string libraryPath, Assembly assembly, Nullable<DllImportSearchPath> searchPath, out IntPtr handle)
    {
        RecordAccess($"NATIVELIB_TRYLOAD({libraryPath}, {assembly?.FullName})");
        switch (Mode)
        {
            case RedirectMode.Block:
                throw new SandboxException(ErrorCode.ForbiddenType);
            case RedirectMode.Honeypot:
                handle = IntPtr.Zero;
                return false;
            default:
                handle = IntPtr.Zero;
                return false;
        }
    }

    public static bool TryGetExport(IntPtr handle, string name, out IntPtr procAddress)
    {
        RecordAccess($"NATIVELIB_TRYGETEXPORT(handle=0x{handle.ToInt64():X}, {name})");
        switch (Mode)
        {
            case RedirectMode.Block:
                throw new SandboxException(ErrorCode.ForbiddenType);
            case RedirectMode.Honeypot:
                procAddress = IntPtr.Zero;
                return false;
            default:
                procAddress = IntPtr.Zero;
                return false;
        }
    }

    public static Delegate GetDelegateForFunctionPointer(IntPtr ptr, Type delegateType)
    {
        RecordAccess($"MARSHAL_GETDELEGATE(ptr=0x{ptr.ToInt64():X}, {delegateType.Name})");
        switch (Mode)
        {
            case RedirectMode.Block:
                throw new SandboxException(ErrorCode.ForbiddenType);
            case RedirectMode.Honeypot:
                return default(Delegate)!;
            default:
                return default(Delegate)!;
        }
    }

    public static TDelegate GetDelegateForFunctionPointer<TDelegate>(IntPtr ptr) where TDelegate : Delegate
    {
        RecordAccess($"MARSHAL_GETDELEGATE_GENERIC(ptr=0x{ptr.ToInt64():X}, {typeof(TDelegate).Name})");
        switch (Mode)
        {
            case RedirectMode.Block:
                throw new SandboxException(ErrorCode.ForbiddenType);
            case RedirectMode.Honeypot:
                return null!;
            default:
                return null!;
        }
    }

    public static IntPtr GetFunctionPointerForDelegate(Delegate d)
    {
        RecordAccess($"MARSHAL_GETFUNCPTR({d?.GetType().Name})");
        switch (Mode)
        {
            case RedirectMode.Block:
                throw new SandboxException(ErrorCode.ForbiddenType);
            case RedirectMode.Honeypot:
                return IntPtr.Zero;
            default:
                return IntPtr.Zero;
        }
    }

    public static IntPtr GetFunctionPointerForDelegate<TDelegate>(TDelegate d) where TDelegate : Delegate
    {
        RecordAccess($"MARSHAL_GETFUNCPTR_GENERIC({typeof(TDelegate).Name})");
        switch (Mode)
        {
            case RedirectMode.Block:
                throw new SandboxException(ErrorCode.ForbiddenType);
            case RedirectMode.Honeypot:
                return IntPtr.Zero;
            default:
                return IntPtr.Zero;
        }
    }

    private static void RecordAccess(string operation)
    {
        AccessLog.Add($"[{DateTime.Now:HH:mm:ss}] {operation}");
    }

    public static IReadOnlyList<string> GetAccessLog() => AccessLog.AsReadOnly();
}
