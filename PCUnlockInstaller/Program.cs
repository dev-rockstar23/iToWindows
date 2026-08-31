// Feature: pc-unlock — Installer/Uninstaller entry point.
// Requirements: 11.1-11.4

using PCUnlockInstaller;

if (args.Length == 0 || args[0] == "--help")
{
    Console.WriteLine("Usage: PCUnlockInstaller install|uninstall");
    return 0;
}

return args[0].ToLowerInvariant() switch
{
    "install" => RunInstall(),
    "uninstall" => RunUninstall(),
    _ => Error($"Unknown command: {args[0]}")
};

static int RunInstall()
{
    bool ok = InstallSequence.Run(out string error);
    if (!ok) { Console.Error.WriteLine($"Install failed: {error}"); return 1; }
    return 0;
}

static int RunUninstall()
{
    bool ok = UninstallSequence.Run(out string error);
    if (!ok) { Console.Error.WriteLine($"Uninstall failed: {error}"); return 1; }
    return 0;
}

static int Error(string msg) { Console.Error.WriteLine(msg); return 1; }
