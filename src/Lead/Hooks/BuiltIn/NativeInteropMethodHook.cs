namespace Lead.Hooks.BuiltIn;

public class NativeInteropMethodHook : IMethodHook
{
    public string Category => "NativeInterop";

    public IEnumerable<MethodHookRule> GetRules()
    {
        var proxyType = typeof(Proxies.NativeInteropProxy);

        yield return new("System.Runtime.InteropServices.NativeLibrary", "Load", proxyType, "Load", "Hook NativeLibrary.Load");
        yield return new("System.Runtime.InteropServices.NativeLibrary", "GetExport", proxyType, "GetExport", "Hook NativeLibrary.GetExport");
        yield return new("System.Runtime.InteropServices.NativeLibrary", "Free", proxyType, "Free", "Hook NativeLibrary.Free");
        yield return new("System.Runtime.InteropServices.NativeLibrary", "TryLoad", proxyType, "TryLoad", "Hook NativeLibrary.TryLoad");
        yield return new("System.Runtime.InteropServices.NativeLibrary", "TryGetExport", proxyType, "TryGetExport", "Hook NativeLibrary.TryGetExport");
        yield return new("System.Runtime.InteropServices.Marshal", "GetDelegateForFunctionPointer", proxyType, "GetDelegateForFunctionPointer", "Hook Marshal.GetDelegateForFunctionPointer");
        yield return new("System.Runtime.InteropServices.Marshal", "GetFunctionPointerForDelegate", proxyType, "GetFunctionPointerForDelegate", "Hook Marshal.GetFunctionPointerForDelegate");
    }
}
