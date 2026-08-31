// Feature: pc-unlock, Property 1
// Feature: pc-unlock, Property 2
//
// InstallerPropertyTests — property-based tests for installer gate and snapshot completeness.
//
// Property 1: Installer gate rejects absent alternative provider — Requirements 1.5, 1.6, 11.2
// Property 2: Provider snapshot completeness              — Requirements 11.1, 11.3

using FsCheck;
using FsCheck.Fluent;
using FsCheck.Xunit;
using PCUnlockInstaller;
using Xunit;

namespace PCUnlockInstaller.Tests;

// ===========================================================================
// Property 1 — Installer gate rejects absent alternative provider
// ===========================================================================

/// <summary>
/// Property 1: VerifyGate accepts iff the snapshot contains at least one
/// non-PCUnlock CLSID.
/// Validates: Requirements 1.5, 1.6, 11.2
/// </summary>
public sealed class InstallerGatePropertyTests
{
    [Fact]
    public void VerifyGate_NonPCUnlockCLSID_ReturnsTrue()
    {
        // Feature: pc-unlock, Property 1
        var snap = new ProviderSnapshot();
        snap.Clsids.Add("{11111111-1111-1111-1111-111111111111}");
        Assert.True(snap.VerifyGate());
    }

    [Fact]
    public void VerifyGate_EmptyList_ReturnsFalse()
    {
        // Feature: pc-unlock, Property 1
        var snap = new ProviderSnapshot();
        Assert.False(snap.VerifyGate());
    }

    [Fact]
    public void VerifyGate_OnlyPCUnlockCLSID_ReturnsFalse()
    {
        // Feature: pc-unlock, Property 1
        var snap = new ProviderSnapshot();
        snap.Clsids.Add(ProviderSnapshot.PCUnlockClsid);
        Assert.False(snap.VerifyGate());
    }

    [Fact]
    public void VerifyGate_PCUnlockPlusAlternative_ReturnsTrue()
    {
        // Feature: pc-unlock, Property 1
        var snap = new ProviderSnapshot();
        snap.Clsids.Add(ProviderSnapshot.PCUnlockClsid);
        snap.Clsids.Add("{AAAAAAAA-AAAA-AAAA-AAAA-AAAAAAAAAAAA}");
        Assert.True(snap.VerifyGate());
    }

    /// <summary>
    /// For any list of CLSIDs, VerifyGate returns true iff at least one is
    /// not the PCUnlock CLSID.
    /// Validates: Requirements 1.5, 1.6, 11.2
    /// </summary>
    [Property(MaxTest = 100)]
    public Property AnyNonPCUnlockCLSID_GateAccepts()
    {
        // Feature: pc-unlock, Property 1
        return Prop.ForAll(
            ArbMap.Default.GeneratorFor<NonEmptyString>()
               .Select(s => s.Get)
               .Where(s => !s.Equals(ProviderSnapshot.PCUnlockClsid,
                   StringComparison.OrdinalIgnoreCase))
               .ToArbitrary(),
            (string clsid) =>
            {
                var snap = new ProviderSnapshot();
                snap.Clsids.Add(clsid);
                return snap.VerifyGate()
                    .Label($"VerifyGate must accept when non-PCUnlock CLSID '{clsid}' is present");
            });
    }

    [Property(MaxTest = 100)]
    public Property OnlyPCUnlockCLSID_GateRejects()
    {
        // Feature: pc-unlock, Property 1
        // For any N ≥ 0 copies of the PCUnlock CLSID, gate must reject.
        return Prop.ForAll(
            Gen.Choose(1, 5).ToArbitrary(),
            count =>
            {
                var snap = new ProviderSnapshot();
                for (int i = 0; i < count; i++)
                    snap.Clsids.Add(ProviderSnapshot.PCUnlockClsid);
                return (!snap.VerifyGate())
                    .Label("VerifyGate must reject when only PCUnlock CLSID is present");
            });
    }
}

// ===========================================================================
// Property 2 — Provider snapshot completeness
// ===========================================================================

/// <summary>
/// Property 2: For any set of active provider CLSIDs at snapshot time, the
/// snapshot records all of them so that a subsequent diff against the same
/// state returns no missing entries.
/// Validates: Requirements 11.1, 11.3
/// </summary>
public sealed class ProviderSnapshotCompletenessTests
{
    [Fact]
    public void DiffProviders_SameSnapshot_NoMissing()
    {
        // Feature: pc-unlock, Property 2
        var snap = new ProviderSnapshot();
        snap.Clsids.AddRange(new[] { "{AAA}", "{BBB}", "{CCC}" });
        var missing = snap.DiffProviders(snap);
        Assert.Empty(missing);
    }

    [Fact]
    public void DiffProviders_RemovedEntry_DetectsMissing()
    {
        // Feature: pc-unlock, Property 2
        var before = new ProviderSnapshot();
        before.Clsids.Add("{AAA}");
        before.Clsids.Add("{BBB}");

        var after = new ProviderSnapshot();
        after.Clsids.Add("{AAA}");

        var missing = before.DiffProviders(after);
        Assert.Single(missing);
        Assert.Equal("{BBB}", missing[0]);
    }

    [Fact]
    public void DiffProviders_NoEntriesRemoved_ReturnsEmpty()
    {
        // Feature: pc-unlock, Property 2
        var before = new ProviderSnapshot();
        before.Clsids.AddRange(new[] { "{AAA}", "{BBB}" });

        var after = new ProviderSnapshot();
        after.Clsids.AddRange(new[] { "{AAA}", "{BBB}", "{CCC}" }); // extra OK

        Assert.Empty(before.DiffProviders(after));
    }

    /// <summary>
    /// For any list of CLSIDs recorded in a snapshot, comparing against the
    /// same list returns no missing entries.
    /// Validates: Requirements 11.1, 11.3
    /// </summary>
    [Property(MaxTest = 100)]
    public Property SnapshotComparedAgainstItself_HasNoMissingEntries()
    {
        // Feature: pc-unlock, Property 2
        return Prop.ForAll(
            Gen.Choose(0, 10)
               .SelectMany(count =>
                   Gen.ListOf(
                       ArbMap.Default.GeneratorFor<NonEmptyString>().Select(s => s.Get),
                       count))
               .ToArbitrary(),
            (List<string> clsids) =>
            {
                var snap = new ProviderSnapshot();
                snap.Clsids.AddRange(clsids);
                var missing = snap.DiffProviders(snap);
                return (missing.Count == 0)
                    .Label("A snapshot compared against itself must have no missing entries");
            });
    }
}

// ===========================================================================
// Install / Uninstall integration tests
// ===========================================================================

public sealed class InstallUninstallTests
{
    [Fact]
    public void InstallSequence_NoAlternativeProvider_Aborts()
    {
        // Feature: pc-unlock — Requirements 1.5, 11.2
        var snap = new ProviderSnapshot(); // empty — no alternative provider
        Assert.False(snap.VerifyGate());
    }

    [Fact]
    public void UninstallSequence_Run_Succeeds()
    {
        // Feature: pc-unlock — Requirements 1.3, 11.3
        bool ok = UninstallSequence.Run(out string error);
        Assert.True(ok);
        Assert.Empty(error);
    }

    [Fact]
    public void ProviderSnapshot_DiffEmpty_WhenNoProvidersMissing()
    {
        // Feature: pc-unlock — Property 2
        var snap = new ProviderSnapshot();
        snap.Clsids.Add("{DEADBEEF-0000-0000-0000-000000000001}");
        var after = new ProviderSnapshot();
        after.Clsids.Add("{DEADBEEF-0000-0000-0000-000000000001}");
        Assert.Empty(snap.DiffProviders(after));
    }
}
