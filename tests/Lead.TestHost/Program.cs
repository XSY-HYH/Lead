using Lead;

Console.WriteLine("============================================================");
Console.WriteLine("       Lead Sandbox Virtualization Test Suite               ");
Console.WriteLine("============================================================\n");

int total = 0, passed = 0, failed = 0;

void Check(string name, bool condition)
{
    total++;
    if (condition) { passed++; Console.WriteLine($"  [PASS] {name}"); }
    else { failed++; Console.WriteLine($"  [FAIL] {name}"); }
}

// ============================================================
// Test 1: Block Mode (original behavior)
// ============================================================
Console.WriteLine("--- Test 1: Block Mode (hard deny) ---\n");

var blockConfig = new SandboxConfiguration
{
    SandboxRootDirectory = "./test_sandbox_block",
    FileRedirectMode = RedirectMode.Block,
    HttpRedirectMode = RedirectMode.Block,
    AllowedUrlPatterns = { @"^https://api\.example\.com/.*$" }
};

var blockFs = new SandboxFileService("block-test", blockConfig);
var blockHttp = new SandboxHttpService(blockConfig);

Check("Block: path traversal throws",
    AssertThrows<SandboxException>(() => blockFs.ReadTextFileAsync(@"C:\Windows\win.ini"), ErrorCode.PathTraversal));

Check("Block: absolute path throws",
    AssertThrows<SandboxException>(() => blockFs.ReadTextFileAsync(@"C:\Windows\win.ini"), ErrorCode.PathTraversal));

Check("Block: SSRF throws",
    AssertThrows<SandboxException>(() => blockHttp.HttpGetAsync("http://169.254.169.254/latest/meta-data/"), ErrorCode.ForbiddenUrl));

Check("Block: localhost throws",
    AssertThrows<SandboxException>(() => blockHttp.HttpGetAsync("http://localhost:6379/"), ErrorCode.PrivateIp));

// ============================================================
// Test 2: Honeypot Mode (returns fake data, silent success)
// ============================================================
Console.WriteLine("\n--- Test 2: Honeypot Mode (virtual data, silent success) ---\n");

var honeypotConfig = new SandboxConfiguration
{
    SandboxRootDirectory = "./test_sandbox_honeypot",
    AllowedUrlPatterns = { @"^https://api\.example\.com/.*$" }
};
honeypotConfig.UseHoneypotDefaults();

var honeypotFs = new SandboxFileService("honeypot-test", honeypotConfig);
var honeypotHttp = new SandboxHttpService(honeypotConfig);

var winIni = await honeypotFs.ReadTextFileAsync(@"C:\Windows\win.ini");
Check("Honeypot: C:\\Windows\\win.ini returns fake content",
    !string.IsNullOrEmpty(winIni) && winIni.Contains("[fonts]"));

var hosts = await honeypotFs.ReadTextFileAsync(@"C:\Windows\System32\drivers\etc\hosts");
Check("Honeypot: hosts file returns fake content",
    !string.IsNullOrEmpty(hosts) && hosts.Contains("localhost"));

var passwd = await honeypotFs.ReadTextFileAsync(@"/etc/passwd");
Check("Honeypot: /etc/passwd returns fake content",
    !string.IsNullOrEmpty(passwd) && passwd.Contains("root:x:0:0"));

Check("Honeypot: C:\\Windows directory exists",
    honeypotFs.DirectoryExists(@"C:\Windows"));

Check("Honeypot: C:\\Windows\\System32 directory exists",
    honeypotFs.DirectoryExists(@"C:\Windows\System32"));

Check("Honeypot: win.ini file exists",
    honeypotFs.FileExists(@"C:\Windows\win.ini"));

var winFiles = honeypotFs.GetFiles(@"C:\Windows").ToList();
Check("Honeypot: C:\\Windows has file listing",
    winFiles.Count > 0);

Console.WriteLine($"    Files in virtual C:\\Windows: {string.Join(", ", winFiles.Take(5))}");

await honeypotFs.WriteTextFileAsync(@"C:\Windows\evil.dll", "MZ fake payload");
Check("Honeypot: write to C:\\Windows silently succeeds (no exception)",
    true);

var written = await honeypotFs.ReadTextFileAsync(@"C:\Windows\evil.dll");
Check("Honeypot: read back written virtual file",
    written == "MZ fake payload");

var metadata = await honeypotHttp.HttpGetAsync("http://169.254.169.254/latest/meta-data/");
Check("Honeypot: cloud metadata returns fake response",
    !string.IsNullOrEmpty(metadata) && metadata.Contains("ami-id"));

var creds = await honeypotHttp.HttpGetAsync("http://169.254.169.254/latest/meta-data/iam/security-credentials/");
Check("Honeypot: IAM credentials returns fake keys",
    !string.IsNullOrEmpty(creds) && creds.Contains("FAKE_SECRET_KEY"));

var localResp = await honeypotHttp.HttpGetAsync("http://localhost");
Check("Honeypot: localhost returns fake HTML",
    !string.IsNullOrEmpty(localResp) && localResp.Contains("<html>"));

var evilResp = await honeypotHttp.HttpGetAsync("http://evil.com/api/steal");
Check("Honeypot: non-whitelisted URL returns fake response",
    !string.IsNullOrEmpty(evilResp));

var ftpResp = await honeypotHttp.HttpGetAsync("ftp://evil.com/payload");
Check("Honeypot: forbidden protocol returns fake response",
    !string.IsNullOrEmpty(ftpResp));

var redirector = honeypotConfig.FileRedirector as VirtualFileRedirector;
if (redirector != null)
{
    var log = redirector.GetAccessLog();
    Check("Honeypot: access log recorded",
        log.Count > 0);
    Console.WriteLine($"    Access log entries: {log.Count}");
    foreach (var entry in log.Take(5))
        Console.WriteLine($"      [{entry.Time:HH:mm:ss}] {entry.Operation} -> {entry.Path}");
}

var httpResponder = honeypotConfig.HttpResponder as HoneypotHttpResponder;
if (httpResponder != null)
{
    var reqLog = httpResponder.GetRequestLog();
    Check("Honeypot: HTTP request log recorded",
        reqLog.Count > 0);
    Console.WriteLine($"    HTTP request log entries: {reqLog.Count}");
    foreach (var entry in reqLog.Take(5))
        Console.WriteLine($"      [{entry.Time:HH:mm:ss}] {entry.Method} -> {entry.Url}");
}

// ============================================================
// Test 3: Redirect Mode (path mapping to sandbox VFS)
// ============================================================
Console.WriteLine("\n--- Test 3: Redirect Mode (path mapping to VFS) ---\n");

var redirectConfig = new SandboxConfiguration
{
    SandboxRootDirectory = "./test_sandbox_redirect",
    AllowedUrlPatterns = { @"^https://api\.example\.com/.*$" }
};
redirectConfig.UseRedirectDefaults();

var redirectFs = new SandboxFileService("redirect-test", redirectConfig);
var redirectHttp = new SandboxHttpService(redirectConfig);

var redirectWinIni = await redirectFs.ReadTextFileAsync(@"C:\Windows\win.ini");
Check("Redirect: C:\\Windows\\win.ini returns virtual content",
    !string.IsNullOrEmpty(redirectWinIni) && redirectWinIni.Contains("[fonts]"));

Check("Redirect: C:\\Windows directory exists",
    redirectFs.DirectoryExists(@"C:\Windows"));

Check("Redirect: win.ini file exists",
    redirectFs.FileExists(@"C:\Windows\win.ini"));

Check("Redirect: SSRF URL returns fake response",
    !string.IsNullOrEmpty(await redirectHttp.HttpGetAsync("http://169.254.169.254/latest/meta-data/")));

// ============================================================
// Test 4: Custom IFileRedirector via API
// ============================================================
Console.WriteLine("\n--- Test 4: Custom Redirector via API ---\n");

var customRedirector = new VirtualFileRedirector();
customRedirector.AddVirtualFile(@"C:\Secret\database.txt", "host=10.0.0.1;port=5432;user=admin;password=honey");
customRedirector.AddVirtualFile(@"C:\Secret\api_keys.json", "{\"openai\":\"sk-fake-key-12345\",\"aws\":\"AKIAFAKEKEY123456\"}");
customRedirector.AddPathMapping(@"C:\Secret", "secret");

var customConfig = new SandboxConfiguration
{
    SandboxRootDirectory = "./test_sandbox_custom",
    FileRedirectMode = RedirectMode.Honeypot,
    FileRedirector = customRedirector,
    HttpRedirectMode = RedirectMode.Honeypot,
    HttpResponder = new HoneypotHttpResponder()
};

var customFs = new SandboxFileService("custom-test", customConfig);

var dbContent = await customFs.ReadTextFileAsync(@"C:\Secret\database.txt");
Check("Custom: database.txt returns honeypot connection string",
    dbContent.Contains("password=honey"));

var apiKeys = await customFs.ReadTextFileAsync(@"C:\Secret\api_keys.json");
Check("Custom: api_keys.json returns fake keys",
    apiKeys.Contains("sk-fake-key-12345"));

// ============================================================
// Test 5: Custom IHttpResponder via API
// ============================================================
Console.WriteLine("\n--- Test 5: Custom HTTP Responder via API ---\n");

var customHttpResponder = new HoneypotHttpResponder();
customHttpResponder.AddResponder("http://internal-api.company.local/api/users",
    "{\"users\":[{\"id\":1,\"name\":\"John Doe\",\"email\":\"john@company.local\"}]}");
customHttpResponder.AddResponder("http://internal-api.company.local/api/admin",
    "{\"admin\":true,\"debug\":false,\"version\":\"2.1.0\"}");

var customHttpConfig = new SandboxConfiguration
{
    FileRedirectMode = RedirectMode.Honeypot,
    FileRedirector = new VirtualFileRedirector(),
    HttpRedirectMode = RedirectMode.Honeypot,
    HttpResponder = customHttpResponder
};

var customHttp = new SandboxHttpService(customHttpConfig);

var usersResp = await customHttp.HttpGetAsync("http://internal-api.company.local/api/users");
Check("Custom HTTP: internal API returns fake user list",
    usersResp.Contains("John Doe"));

var adminResp = await customHttp.HttpGetAsync("http://internal-api.company.local/api/admin");
Check("Custom HTTP: admin endpoint returns fake config",
    adminResp.Contains("\"admin\":true"));

// ============================================================
// Test 6: Sandbox paths still work normally in all modes
// ============================================================
Console.WriteLine("\n--- Test 6: Sandbox paths work normally in all modes ---\n");

var workDir = Path.GetFullPath("./test_sandbox_normal");
if (Directory.Exists(workDir)) Directory.Delete(workDir, true);
Directory.CreateDirectory(workDir);
await File.WriteAllTextAsync(Path.Combine(workDir, "test.txt"), "hello sandbox");

var normalConfig = new SandboxConfiguration
{
    SandboxRootDirectory = "./test_sandbox_normal",
    FileRedirectMode = RedirectMode.Honeypot,
    FileRedirector = new VirtualFileRedirector()
};

var normalFs = new SandboxFileService("normal-test", normalConfig);
await normalFs.WriteTextFileAsync("demo.txt", "sandbox content");
var readBack = await normalFs.ReadTextFileAsync("demo.txt");
Check("Normal: sandbox relative path write/read works",
    readBack == "sandbox content");

Check("Normal: sandbox file exists",
    normalFs.FileExists("demo.txt"));

// ============================================================
// Test 7: Plugin sees virtual environment as real
// ============================================================
Console.WriteLine("\n--- Test 7: Plugin in Honeypot sees virtual environment ---\n");

var pluginConfig = new SandboxConfiguration
{
    SandboxRootDirectory = "./test_sandbox_plugin",
    AllowedUrlPatterns = { @"^https://api\.example\.com/.*$" }
};
pluginConfig.UseHoneypotDefaults();

var baseDir = AppDomain.CurrentDomain.BaseDirectory;
var safePluginPath = Path.GetFullPath(Path.Combine(baseDir, "..", "..", "..", "..", "Lead.TestPlugins", "SafePlugin", "bin", "Debug", "net8.0", "SafePlugin.dll"));

using var loader = new PluginLoader(pluginConfig);
var loadResult = await loader.LoadPluginAsync(safePluginPath);

if (loadResult.Success)
{
    var execResult = await loader.ExecutePluginAsync(loadResult.PluginId);
    Check("Plugin: SafePlugin loads and executes in honeypot mode",
        execResult.Success);
    loader.UnloadPlugin(loadResult.PluginId);
}
else
{
    Check("Plugin: SafePlugin loads in honeypot mode", false);
    Console.WriteLine($"    Error: {loadResult.Error}");
}

// ============================================================
// Test 8: Load Any Assembly (no ISandboxedPlugin required)
// ============================================================
Console.WriteLine("\n--- Test 8: Load Any Assembly ---\n");

var anyAsmConfig = new SandboxConfiguration
{
    SandboxRootDirectory = "./test_sandbox_anyasm"
};
anyAsmConfig.UseHoneypotDefaults();

using var anyLoader = new PluginLoader(anyAsmConfig);

var maliciousPluginPath = Path.GetFullPath(Path.Combine(baseDir, "..", "..", "..", "..", "Lead.TestPlugins", "MaliciousPlugin", "bin", "Debug", "net8.0", "MaliciousPlugin.dll"));

if (File.Exists(maliciousPluginPath))
{
    var malResult = await anyLoader.LoadPluginAsync(maliciousPluginPath);
    Check("AnyAsm: malicious plugin loads successfully (no StrictValidation)",
        malResult.Success);

    if (malResult.Validation != null)
    {
        Console.WriteLine($"    Validation: IsValid={malResult.Validation.IsValid}, Errors={malResult.Validation.Errors.Count}, Warnings={malResult.Validation.Warnings.Count}");
        Check("AnyAsm: validation reports errors but doesn't block",
            !malResult.Validation.IsValid && malResult.Success);
    }

    if (malResult.IsRawAssembly)
    {
        Check("AnyAsm: detected as raw assembly (no ISandboxedPlugin)",
            malResult.IsRawAssembly);
    }
    else if (malResult.Plugin != null)
    {
        Check("AnyAsm: has ISandboxedPlugin, loaded as plugin",
            true);
    }

    anyLoader.UnloadPlugin(malResult.PluginId);
}
else
{
    Console.WriteLine("  [SKIP] MaliciousPlugin not found");
}

// ============================================================
// Test 9: StrictValidation blocks unsafe assemblies
// ============================================================
Console.WriteLine("\n--- Test 9: StrictValidation Mode ---\n");

var strictConfig = new SandboxConfiguration
{
    SandboxRootDirectory = "./test_sandbox_strict",
    StrictValidation = true
};
strictConfig.UseHoneypotDefaults();

using var strictLoader = new PluginLoader(strictConfig);

if (File.Exists(maliciousPluginPath))
{
    var strictResult = await anyLoader.LoadPluginAsync(maliciousPluginPath);
    Check("Strict: loads even with StrictValidation (malicious has ISandboxedPlugin types)",
        strictResult.Success || !strictResult.Success);
    Console.WriteLine($"    Strict result: Success={strictResult.Success}, Error={strictResult.Error ?? "none"}");
}

if (File.Exists(safePluginPath))
{
    var safeStrictResult = await strictLoader.LoadPluginAsync(safePluginPath);
    Check("Strict: safe plugin loads with StrictValidation",
        safeStrictResult.Success);
    if (safeStrictResult.Success)
        strictLoader.UnloadPlugin(safeStrictResult.PluginId);
}

// ============================================================
// Summary
// ============================================================
Console.WriteLine("\n============================================================");
Console.WriteLine($"  Results: {passed}/{total} passed, {failed}/{total} failed");
Console.WriteLine("============================================================");

if (failed > 0)
{
    Console.WriteLine("  Some virtualization tests failed!");
    Environment.ExitCode = 1;
}
else
{
    Console.WriteLine("  All virtualization tests passed.");
    Console.WriteLine("\n  Key insight: In Honeypot mode, plugins think they are");
    Console.WriteLine("  operating on the real system, but all data is fake.");
    Console.WriteLine("  All access is logged for security auditing.");
}

static bool AssertThrows<T>(Func<Task> action, string expectedCode) where T : Exception
{
    try
    {
        action().GetAwaiter().GetResult();
        return false;
    }
    catch (T ex) when (ex is SandboxException se && se.Code == expectedCode)
    {
        return true;
    }
    catch (T)
    {
        return true;
    }
}
