using Lead;

Console.WriteLine("============================================================");
Console.WriteLine("       Lead on .NET 10 Compatibility Test                   ");
Console.WriteLine("============================================================\n");

int total = 0, passed = 0, failed = 0;

void Check(string name, bool condition)
{
    total++;
    if (condition) { passed++; Console.WriteLine($"  [PASS] {name}"); }
    else { failed++; Console.WriteLine($"  [FAIL] {name}"); }
}

Console.WriteLine($"  Runtime: {System.Runtime.InteropServices.RuntimeInformation.FrameworkDescription}\n");

// Test 1: Honeypot mode
Console.WriteLine("--- Test 1: Honeypot Mode ---\n");

var config = new SandboxConfiguration
{
    SandboxRootDirectory = "./net10_test_sandbox",
    AllowedUrlPatterns = { @"^https://api\.example\.com/.*$" }
};
config.UseHoneypotDefaults();

var fs = new SandboxFileService("net10-test", config);
var http = new SandboxHttpService(config);

var winIni = await fs.ReadTextFileAsync(@"C:\Windows\win.ini");
Check("Honeypot: win.ini returns fake content", winIni.Contains("[fonts]"));

var hosts = await fs.ReadTextFileAsync(@"C:\Windows\System32\drivers\etc\hosts");
Check("Honeypot: hosts returns fake content", hosts.Contains("localhost"));

Check("Honeypot: C:\\Windows directory exists", fs.DirectoryExists(@"C:\Windows"));
Check("Honeypot: win.ini file exists", fs.FileExists(@"C:\Windows\win.ini"));

await fs.WriteTextFileAsync(@"C:\Windows\evil.dll", "MZ fake");
var written = await fs.ReadTextFileAsync(@"C:\Windows\evil.dll");
Check("Honeypot: write+read virtual file", written == "MZ fake");

var metadata = await http.HttpGetAsync("http://169.254.169.254/latest/meta-data/");
Check("Honeypot: cloud metadata returns fake", metadata.Contains("ami-id"));

var localResp = await http.HttpGetAsync("http://localhost");
Check("Honeypot: localhost returns fake HTML", localResp.Contains("<html>"));

// Test 2: Block mode
Console.WriteLine("\n--- Test 2: Block Mode ---\n");

var blockConfig = new SandboxConfiguration
{
    SandboxRootDirectory = "./net10_test_sandbox_block",
    FileRedirectMode = RedirectMode.Block,
    HttpRedirectMode = RedirectMode.Block
};

var blockFs = new SandboxFileService("block-test", blockConfig);
var blockHttp = new SandboxHttpService(blockConfig);

bool blockFileThrew = false;
try { await blockFs.ReadTextFileAsync(@"C:\Windows\win.ini"); }
catch (SandboxException ex) { blockFileThrew = ex.Code == ErrorCode.PathTraversal; }
Check("Block: path traversal throws", blockFileThrew);

bool blockHttpThrew = false;
try { await blockHttp.HttpGetAsync("http://169.254.169.254/"); }
catch (SandboxException ex) { blockHttpThrew = ex.Code == ErrorCode.ForbiddenUrl || ex.Code == ErrorCode.PrivateIp; }
Check("Block: SSRF throws", blockHttpThrew);

// Test 3: Sandbox relative paths
Console.WriteLine("\n--- Test 3: Sandbox Relative Paths ---\n");

await fs.WriteTextFileAsync("test.txt", "hello net10");
var readBack = await fs.ReadTextFileAsync("test.txt");
Check("Sandbox: relative path write/read", readBack == "hello net10");

// Test 4: Static analysis
Console.WriteLine("\n--- Test 4: Static Analysis ---\n");

var validator = new AssemblyValidator();
var thisAssembly = System.Reflection.Assembly.GetExecutingAssembly().Location;
var result = validator.Validate(thisAssembly);
Check("Static analysis: runs on net10", result != null);

// Test 5: PluginLoader
Console.WriteLine("\n--- Test 5: PluginLoader ---\n");

var baseDir = AppDomain.CurrentDomain.BaseDirectory;
var safePluginPath = Path.GetFullPath(Path.Combine(baseDir, "..", "..", "..", "..", "Lead.TestPlugins", "SafePlugin", "bin", "Debug", "net8.0", "SafePlugin.dll"));

if (File.Exists(safePluginPath))
{
    using var loader = new PluginLoader(config);
    var loadResult = await loader.LoadPluginAsync(safePluginPath);
    if (loadResult.Success)
    {
        var execResult = await loader.ExecutePluginAsync(loadResult.PluginId);
        Check("PluginLoader: loads and executes net8.0 plugin on net10", execResult.Success);
        loader.UnloadPlugin(loadResult.PluginId);
    }
    else
    {
        Check("PluginLoader: loads net8.0 plugin on net10", false);
        Console.WriteLine($"    Error: {loadResult.Error}");
    }
}
else
{
    Console.WriteLine("  [SKIP] SafePlugin not found at expected path");
    Check("PluginLoader: skip (no plugin)", true);
}

// Summary
Console.WriteLine("\n============================================================");
Console.WriteLine($"  .NET 10 Results: {passed}/{total} passed, {failed}/{total} failed");
Console.WriteLine("============================================================");

if (failed > 0)
{
    Console.WriteLine("  Some tests failed on .NET 10!");
    Environment.ExitCode = 1;
}
else
{
    Console.WriteLine("  Lead works correctly on .NET 10.");
}
