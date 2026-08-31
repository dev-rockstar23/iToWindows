// Feature: pc-unlock
// ProviderSnapshot — enumerates, persists, and diffs Windows Credential Provider CLSIDs.
// Requirements: 1.5, 1.6, 11.1, 11.2, 11.3

using System.Text.Json;
using Microsoft.Win32;

namespace PCUnlockInstaller;

/// <summary>
/// Records all active Credential Provider CLSIDs at a point in time and
/// supports gate-checking and diffing against a later snapshot.
/// </summary>
public sealed class ProviderSnapshot
{
    // The PCUnlock CP CLSID — excluded from alternative-provider checks.
    public const string PCUnlockClsid = "{7B3E5A9C-2F4D-4A8B-9C1E-3D6F8A0B2E4C}";

    private static readonly string RegPath =
        @"SOFTWARE\Microsoft\Windows\CurrentVersion\Authentication\Credential Providers";

    private static readonly JsonSerializerOptions JsonOpts = new() { WriteIndented = true };

    /// <summary>All CLSID strings found under the Credential Providers registry key.</summary>
    public List<string> Clsids { get; } = new();

    /// <summary>UTC timestamp when this snapshot was taken.</summary>
    public DateTimeOffset TakenAt { get; init; } = DateTimeOffset.UtcNow;

    // -------------------------------------------------------------------------
    // Factory
    // -------------------------------------------------------------------------

    /// <summary>
    /// Enumerates all Credential Provider CLSIDs from the registry and returns
    /// a <see cref="ProviderSnapshot"/> (Requirement 11.1).
    /// </summary>
    public static ProviderSnapshot TakeSnapshot()
    {
        var snap = new ProviderSnapshot();
        using var key = Registry.LocalMachine.OpenSubKey(RegPath);
        if (key is null) return snap;

        foreach (var name in key.GetSubKeyNames())
            snap.Clsids.Add(name);

        return snap;
    }

    // -------------------------------------------------------------------------
    // Gate check
    // -------------------------------------------------------------------------

    /// <summary>
    /// Returns <c>true</c> if the snapshot contains at least one non-PCUnlock
    /// CLSID (Requirement 11.2 — must abort installation if this returns false).
    /// </summary>
    public bool VerifyGate() =>
        Clsids.Any(c => !c.Equals(PCUnlockClsid, StringComparison.OrdinalIgnoreCase));

    // -------------------------------------------------------------------------
    // Diff
    // -------------------------------------------------------------------------

    /// <summary>
    /// Returns CLSIDs present in <c>this</c> snapshot that are absent in
    /// <paramref name="after"/>. A non-empty result means a provider was lost
    /// and must be restored (Requirements 11.3, 11.4).
    /// </summary>
    public List<string> DiffProviders(ProviderSnapshot after) =>
        Clsids
            .Where(c => !after.Clsids.Contains(c, StringComparer.OrdinalIgnoreCase))
            .ToList();

    // -------------------------------------------------------------------------
    // Persistence
    // -------------------------------------------------------------------------

    /// <summary>
    /// Serialises the snapshot to JSON and writes it to
    /// <c>%PROGRAMDATA%\PCUnlock\provider_snapshot.json</c>.
    /// </summary>
    public void Save()
    {
        string dir  = Path.Combine(
            Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData),
            "PCUnlock");
        Directory.CreateDirectory(dir);
        string path = Path.Combine(dir, "provider_snapshot.json");
        File.WriteAllText(path, JsonSerializer.Serialize(this, JsonOpts));
    }

    /// <summary>Loads a previously saved snapshot, or returns <c>null</c> if none exists.</summary>
    public static ProviderSnapshot? Load()
    {
        string path = Path.Combine(
            Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData),
            "PCUnlock",
            "provider_snapshot.json");

        if (!File.Exists(path)) return null;

        try
        {
            return JsonSerializer.Deserialize<ProviderSnapshot>(File.ReadAllText(path));
        }
        catch
        {
            return null;
        }
    }
}
