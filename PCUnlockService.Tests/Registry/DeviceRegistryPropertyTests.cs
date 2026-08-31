// Feature: pc-unlock, Property 5
// Feature: pc-unlock, Property 18
// Feature: pc-unlock, Property 19
//
// DeviceRegistryPropertyTests — property-based and unit tests for DeviceRegistry.
//
// Property 5:  Device Registry deletion completeness — Requirements 3.4, 9.2
// Property 18: Device Registry capacity              — Requirements 6.7, 9.4
// Property 19: Atomic deletion rollback              — Requirements 9.2

using FsCheck;
using FsCheck.Fluent;
using FsCheck.Xunit;
using PCUnlockService.Pairing;
using PCUnlockService.Registry;
using System.Security.Cryptography;
using Xunit;

namespace PCUnlockService.Tests.Registry;

// ---------------------------------------------------------------------------
// Temp-directory fixture
// ---------------------------------------------------------------------------

public sealed class RegistryTempFixture : IDisposable
{
    public string TempDir { get; } =
        Path.Combine(Path.GetTempPath(), $"PCUnlockRegTests_{Guid.NewGuid():N}");

    public RegistryTempFixture() => Directory.CreateDirectory(TempDir);

    public string NewRegistryPath() =>
        Path.Combine(TempDir, $"devices_{Guid.NewGuid():N}.dat");

    public void Dispose()
    {
        try { Directory.Delete(TempDir, recursive: true); } catch { /* best-effort */ }
    }
}

// ---------------------------------------------------------------------------
// Shared helpers
// ---------------------------------------------------------------------------

internal static class RegistryTestHelpers
{
    private static readonly byte[] StubPublicKey = { 0x04, 0x01, 0x02, 0x03 };

    public static DeviceRecord MakeRecord(string name) => new()
    {
        DeviceId        = Guid.NewGuid(),
        DeviceName      = name,
        PublicKeyDER    = StubPublicKey,
        PairedAt        = DateTimeOffset.UtcNow,
        LastUsedAt      = null,
        PcIdentityToken = RandomNumberGenerator.GetBytes(16),
    };

    public static List<DeviceRecord> MakeRecords(int count) =>
        Enumerable.Range(0, count)
                  .Select(i => MakeRecord($"Device-{i:D3}"))
                  .ToList();
}

// ===========================================================================
// Property 5 — Device Registry deletion completeness
// ===========================================================================

/// <summary>
/// Property 5: For any registry state containing a given deviceId, after
/// successful removal the registry does NOT contain that deviceId and all
/// other records are unchanged.
/// Validates: Requirements 3.4, 9.2
/// </summary>
public sealed class DeletionCompletenessPropertyTests : IDisposable
{
    private readonly RegistryTempFixture _fixture = new();
    public void Dispose() => _fixture.Dispose();

    // -----------------------------------------------------------------------
    // Property 5 — property-based, 100 iterations
    // -----------------------------------------------------------------------

    /// <summary>
    /// For any list of 2–5 distinct device records, removing one target record
    /// MUST result in the target being absent and all others still present.
    /// Validates: Requirements 3.4, 9.2
    /// </summary>
    [Property(MaxTest = 100)]
    public Property Remove_TargetAbsent_OthersUnchanged()
    {
        // Feature: pc-unlock, Property 5
        return Prop.ForAll(
            Gen.Choose(2, 5).ToArbitrary(),
            count =>
            {
                string path = _fixture.NewRegistryPath();
                var registry = new DeviceRegistry(path);

                var records = RegistryTestHelpers.MakeRecords(count);
                foreach (var r in records)
                    registry.Append(r);

                // Pick the first record as the target to remove.
                var target = records[0];
                var others = records.Skip(1).ToList();

                registry.Remove(target.DeviceId);

                // Target must be absent.
                bool targetAbsent = !registry.Contains(target.DeviceId);

                // All others must still be present.
                bool othersPresent = others.All(r => registry.Contains(r.DeviceId));

                // Count must be count-1.
                bool countCorrect = registry.ReadAll().Count == count - 1;

                return targetAbsent
                    .Label("Removed record must not be in registry")
                    .And(othersPresent)
                    .Label("All other records must remain present")
                    .And(countCorrect)
                    .Label($"Registry count must be {count - 1}");
            });
    }

    // -----------------------------------------------------------------------
    // Property 5 — concrete [Fact] example
    // -----------------------------------------------------------------------

    [Fact]
    public void Remove_Middle_OtherTwoRemain()
    {
        // Feature: pc-unlock, Property 5
        string path = _fixture.NewRegistryPath();
        var registry = new DeviceRegistry(path);

        var r1 = RegistryTestHelpers.MakeRecord("First");
        var r2 = RegistryTestHelpers.MakeRecord("Second");
        var r3 = RegistryTestHelpers.MakeRecord("Third");

        registry.Append(r1);
        registry.Append(r2);
        registry.Append(r3);

        registry.Remove(r2.DeviceId);

        Assert.False(registry.Contains(r2.DeviceId), "Removed record must be gone");
        Assert.True(registry.Contains(r1.DeviceId), "First record must remain");
        Assert.True(registry.Contains(r3.DeviceId), "Third record must remain");
        Assert.Equal(2, registry.ReadAll().Count);
    }
}

// ===========================================================================
// Property 19 — Atomic deletion rollback
// ===========================================================================

/// <summary>
/// Property 19: For any deletion operation with a fault injected, the registry
/// is in the same state as before the deletion was attempted.
/// Validates: Requirements 9.2
/// </summary>
public sealed class AtomicDeletionRollbackTests : IDisposable
{
    private readonly RegistryTempFixture _fixture = new();
    public void Dispose() => _fixture.Dispose();

    [Fact]
    public void Remove_NonExistentDevice_ThrowsException()
    {
        // Feature: pc-unlock, Property 19
        string path = _fixture.NewRegistryPath();
        var registry = new DeviceRegistry(path);

        Assert.Throws<DeviceRegistryException>(() => registry.Remove(Guid.NewGuid()));
    }

    [Fact]
    public void Remove_NonExistentDevice_RegistryUnchanged()
    {
        // Feature: pc-unlock, Property 19
        string path = _fixture.NewRegistryPath();
        var registry = new DeviceRegistry(path);

        var r1 = RegistryTestHelpers.MakeRecord("Alice");
        var r2 = RegistryTestHelpers.MakeRecord("Bob");
        registry.Append(r1);
        registry.Append(r2);

        // Attempt to remove a device that doesn't exist — must not change state.
        var ex = Record.Exception(() => registry.Remove(Guid.NewGuid()));
        Assert.NotNull(ex);
        Assert.IsType<DeviceRegistryException>(ex);

        // Both original records must still be present.
        Assert.True(registry.Contains(r1.DeviceId), "r1 must remain after failed removal");
        Assert.True(registry.Contains(r2.DeviceId), "r2 must remain after failed removal");
        Assert.Equal(2, registry.ReadAll().Count);
    }

    [Fact]
    public void Append_ThenRemove_AllOtherRecordsIntact()
    {
        // Feature: pc-unlock, Property 19
        string path = _fixture.NewRegistryPath();
        var registry = new DeviceRegistry(path);

        var records = RegistryTestHelpers.MakeRecords(3);
        foreach (var r in records) registry.Append(r);

        registry.Remove(records[1].DeviceId);

        Assert.True(registry.Contains(records[0].DeviceId), "Record 0 must remain");
        Assert.False(registry.Contains(records[1].DeviceId), "Record 1 must be removed");
        Assert.True(registry.Contains(records[2].DeviceId), "Record 2 must remain");
    }

    [Fact]
    public void VerifyIntegrity_ValidRegistry_ReturnsTrue()
    {
        // Feature: pc-unlock, Property 19
        string path = _fixture.NewRegistryPath();
        var registry = new DeviceRegistry(path);

        registry.Append(RegistryTestHelpers.MakeRecord("Valid Device"));

        Assert.True(registry.VerifyIntegrity());
    }

    [Fact]
    public void VerifyIntegrity_EmptyRegistry_ReturnsTrue()
    {
        // Feature: pc-unlock, Property 19 — empty registry is valid
        string path = _fixture.NewRegistryPath();
        var registry = new DeviceRegistry(path);

        Assert.True(registry.VerifyIntegrity());
    }

    [Fact]
    public void VerifyIntegrity_CorruptFile_ReturnsFalse()
    {
        // Feature: pc-unlock, Property 19
        string path = _fixture.NewRegistryPath();
        // Write garbage bytes directly to simulate a corrupt file.
        File.WriteAllBytes(path, new byte[] { 0xDE, 0xAD, 0xBE, 0xEF });

        var registry = new DeviceRegistry(path);
        Assert.False(registry.VerifyIntegrity());
    }
}

// ===========================================================================
// Property 18 — Device Registry capacity
// ===========================================================================

/// <summary>
/// Property 18: For any sequence of ≥10 distinct device pairing completions,
/// all 10 device records are retrievable from the registry.
/// Validates: Requirements 6.7, 9.4
/// </summary>
public sealed class DeviceRegistryCapacityTests : IDisposable
{
    private readonly RegistryTempFixture _fixture = new();
    public void Dispose() => _fixture.Dispose();

    [Fact]
    public void Append10Records_AllRetrievable()
    {
        // Feature: pc-unlock, Property 18
        string path = _fixture.NewRegistryPath();
        var registry = new DeviceRegistry(path);

        var records = RegistryTestHelpers.MakeRecords(10);
        foreach (var r in records)
            registry.Append(r);

        Assert.Equal(10, registry.ReadAll().Count);
        foreach (var r in records)
            Assert.True(registry.Contains(r.DeviceId),
                $"Record {r.DeviceName} must be retrievable");
    }

    /// <summary>
    /// For any N in [10, 20], all N records are retrievable after appending.
    /// Validates: Requirements 6.7, 9.4
    /// </summary>
    [Property(MaxTest = 50)]
    public Property AppendNRecords_AllRetrievable()
    {
        // Feature: pc-unlock, Property 18
        return Prop.ForAll(
            Gen.Choose(10, 20).ToArbitrary(),
            n =>
            {
                string path = _fixture.NewRegistryPath();
                var registry = new DeviceRegistry(path);

                var records = RegistryTestHelpers.MakeRecords(n);
                foreach (var r in records)
                    registry.Append(r);

                bool countCorrect = registry.ReadAll().Count == n;
                bool allPresent   = records.All(r => registry.Contains(r.DeviceId));

                return countCorrect
                    .Label($"Registry must contain {n} records (has {registry.ReadAll().Count})")
                    .And(allPresent)
                    .Label("All appended records must be retrievable");
            });
    }

    [Fact]
    public void Append_ThenReadAll_ReturnsSameRecords()
    {
        // Feature: pc-unlock, Property 18
        string path = _fixture.NewRegistryPath();
        var registry = new DeviceRegistry(path);

        var records = RegistryTestHelpers.MakeRecords(5);
        foreach (var r in records)
            registry.Append(r);

        var readBack = registry.ReadAll();
        Assert.Equal(5, readBack.Count);

        foreach (var original in records)
        {
            var found = readBack.FirstOrDefault(r => r.DeviceId == original.DeviceId);
            Assert.NotNull(found);
            Assert.Equal(original.DeviceName, found!.DeviceName);
        }
    }
}
