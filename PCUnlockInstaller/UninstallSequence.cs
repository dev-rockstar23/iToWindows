// Feature: pc-unlock
// UninstallSequence — safe, snapshot-aware uninstall flow.
// Requirements: 1.3, 1.4, 11.3, 11.4

namespace PCUnlockInstaller;

/// <summary>
/// Executes the PCUnlock uninstall sequence, restoring any providers that
/// were active before PCUnlock was installed.
/// </summary>
public static class UninstallSequence
{
    /// <summary>
    /// Runs the uninstall:
    /// <list type="number">
    ///   <item>Load pre-install provider snapshot.</item>
    ///   <item>Stop PCUnlock_Service and de-register the CP CLSID.</item>
    ///   <item>Re-enumerate providers and compare against snapshot (excluding PCUnlock).</item>
    ///   <item>Restore any missing providers.</item>
    ///   <item>Delete PCUnlock data files and event source registration.</item>
    /// </list>
    /// </summary>
    public static bool Run(out string error)
    {
        error = string.Empty;

        // Step 1: Load snapshot.
        var snapshot = ProviderSnapshot.Load();
        if (snapshot is null)
        {
            Console.WriteLine("[uninstall] No provider snapshot found — skipping provider restoration.");
        }

        // Step 2: Stop service and de-register CP.
        StopService();
        DeregisterCredentialProvider();

        // Step 3: Compare current providers against snapshot.
        if (snapshot is not null)
        {
            var current = ProviderSnapshot.TakeSnapshot();
            // Exclude PCUnlock itself from "after" comparison.
            current.Clsids.Remove(ProviderSnapshot.PCUnlockClsid);

            var missing = snapshot.DiffProviders(current);

            // Step 4: Restore missing providers.
            foreach (var clsid in missing)
            {
                Console.WriteLine($"[uninstall] Restoring provider: {clsid}");
                RestoreProvider(clsid);
            }
        }

        // Step 5: Delete data files.
        DeleteDataFiles();

        Console.WriteLine("PCUnlock uninstalled successfully.");
        return true;
    }

    // -------------------------------------------------------------------------
    // Private helpers (stubbed)
    // -------------------------------------------------------------------------

    private static void StopService()
    {
        Console.WriteLine("[stub] Stopping PCUnlockService.");
    }

    private static void DeregisterCredentialProvider()
    {
        Console.WriteLine($"[stub] De-registering CP CLSID: {ProviderSnapshot.PCUnlockClsid}");
    }

    private static void RestoreProvider(string clsid)
    {
        Console.WriteLine($"[stub] Restoring provider registry entry: {clsid}");
    }

    private static void DeleteDataFiles()
    {
        var appData = Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData);
        var pcUnlockDir = Path.Combine(appData, "PCUnlock");

        foreach (var file in new[] { "devices.dat", "nonces.dat" })
        {
            var path = Path.Combine(pcUnlockDir, file);
            if (File.Exists(path))
            {
                File.Delete(path);
                Console.WriteLine($"[uninstall] Deleted {path}");
            }
        }

        // Delete snapshot.
        var progData = Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData);
        var snapPath = Path.Combine(progData, "PCUnlock", "provider_snapshot.json");
        if (File.Exists(snapPath)) File.Delete(snapPath);

        Console.WriteLine("[stub] Removing PCUnlock event source registration.");
    }
}
