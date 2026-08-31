// Feature: pc-unlock
// InstallSequence — safe, snapshot-backed installation flow.
// Requirements: 1.5, 1.6, 1.7, 11.1, 11.2

namespace PCUnlockInstaller;

/// <summary>
/// Executes the PCUnlock install sequence with pre/post provider snapshot
/// verification and full rollback on mismatch.
/// </summary>
public static class InstallSequence
{
    // Placeholder CLSID — replaced with the real generated CLSID in production.
    public const string PCUnlockClsid = ProviderSnapshot.PCUnlockClsid;

    /// <summary>
    /// Runs the installation:
    /// <list type="number">
    ///   <item>Take pre-install provider snapshot.</item>
    ///   <item>Verify at least one non-PCUnlock provider exists.</item>
    ///   <item>Register PCUnlock CP CLSID.</item>
    ///   <item>Install and start PCUnlock_Service.</item>
    ///   <item>Re-enumerate providers; compare against snapshot.</item>
    ///   <item>Roll back if any snapshot provider is missing.</item>
    /// </list>
    /// </summary>
    /// <returns><c>true</c> on success; <c>false</c> with <paramref name="error"/> on failure.</returns>
    public static bool Run(out string error)
    {
        error = string.Empty;

        // Step 1: Snapshot.
        var before = ProviderSnapshot.TakeSnapshot();
        before.Save();

        // Step 2: Gate check (Requirement 11.2).
        if (!before.VerifyGate())
        {
            error = "Installation aborted: no alternative Windows credential provider found. " +
                    "Install another provider (e.g. PIN, password) before installing PCUnlock.";
            return false;
        }

        // Step 3: Register PCUnlock CP CLSID (stubbed — real registration done by MSI/WiX).
        RegisterCredentialProvider();

        // Step 4: Install and start PCUnlock_Service (stubbed — done by MSI/WiX).
        InstallService();

        // Step 5: Re-enumerate after installation.
        var after = ProviderSnapshot.TakeSnapshot();

        // Step 6: Diff — any providers lost?
        var missing = before.DiffProviders(after);
        if (missing.Count > 0)
        {
            error = $"Installation damaged existing credential providers: [{string.Join(", ", missing)}]. " +
                    "Rolling back.";
            Rollback(missing);
            return false;
        }

        Console.WriteLine("PCUnlock installation complete.");
        return true;
    }

    // -------------------------------------------------------------------------
    // Private helpers (stubbed — real logic in MSI/WiX custom actions)
    // -------------------------------------------------------------------------

    private static void RegisterCredentialProvider()
    {
        // TODO: Write PCUnlock CP CLSID under
        //   HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Authentication\Credential Providers\{CLSID}
        //   and register the COM server DLL.
        Console.WriteLine($"[stub] Registering CP CLSID: {PCUnlockClsid}");
    }

    private static void InstallService()
    {
        // TODO: Install PCUnlockService.exe as a Windows service running as Local Service.
        Console.WriteLine("[stub] Installing PCUnlockService.");
    }

    private static void Rollback(List<string> missingClsids)
    {
        // Restore missing provider registrations.
        foreach (var clsid in missingClsids)
            Console.WriteLine($"[rollback] Restoring provider: {clsid}");

        // De-register PCUnlock CP.
        Console.WriteLine($"[rollback] De-registering {PCUnlockClsid}");

        // Stop and remove service.
        Console.WriteLine("[rollback] Removing PCUnlockService.");
    }
}
