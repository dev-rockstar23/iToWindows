// Feature: pc-unlock, Property 14
// NonceStorePersistencePropertyTests — property-based tests for nonce store
// persistence across simulated service restarts.
// Validates: Requirements 5.7, 13.4

using FsCheck;
using FsCheck.Xunit;
using PCUnlockService.Session;
using System.Security.Cryptography;
using Xunit;

namespace PCUnlockService.Tests.Session;

// ---------------------------------------------------------------------------
// Nonce32 — 32-byte nonce wrapper for FsCheck arbitrary generation
// ---------------------------------------------------------------------------

/// <summary>
/// Value-type wrapper around a 32-byte nonce array.
/// Provides a typed FsCheck <see cref="Arbitrary{T}"/> via
/// <see cref="Arbitrary"/>.
/// </summary>
public readonly record struct Nonce32(byte[] Value)
{
    /// <summary>FsCheck arbitrary that always produces exactly 32 random bytes.</summary>
    public static Arbitrary<Nonce32> Arbitrary() =>
        FsCheck.Arb.From(
            Gen.ArrayOf(32, FsCheck.Arb.Generate<byte>())
               .Select(bytes => new Nonce32(bytes)));
}

// ---------------------------------------------------------------------------
// Temp-directory fixture
// ---------------------------------------------------------------------------

/// <summary>
/// Provides an isolated temporary directory for each test instance and
/// deletes it on disposal.
/// </summary>
public sealed class NonceStorePersistenceFixture : IDisposable
{
    public string TempDir { get; } =
        Path.Combine(Path.GetTempPath(), $"PCUnlockPropTests_{Guid.NewGuid():N}");

    public NonceStorePersistenceFixture()
    {
        Directory.CreateDirectory(TempDir);
    }

    /// <summary>Returns a unique file path inside the isolated temp directory.</summary>
    public string NewStorePath() =>
        Path.Combine(TempDir, $"nonces_{Guid.NewGuid():N}.dat");

    public void Dispose()
    {
        try { Directory.Delete(TempDir, recursive: true); } catch { /* best-effort */ }
    }
}

// ---------------------------------------------------------------------------
// Property 14: Nonce store persistence across restarts
// ---------------------------------------------------------------------------

/// <summary>
/// Property-based tests verifying that nonces written to
/// <see cref="ConsumedNonceStore"/> survive a simulated service restart
/// (i.e., a new store instance backed by the same file, after calling Load()).
/// Validates: Requirements 5.7, 13.4
/// </summary>
public sealed class NonceStorePersistencePropertyTests : IDisposable
{
    private readonly NonceStorePersistenceFixture _fixture = new();

    public void Dispose() => _fixture.Dispose();

    // -----------------------------------------------------------------------
    // Arbitrary generators
    // -----------------------------------------------------------------------

    /// <summary>
    /// Arbitrary for a 32-byte nonce array — matches the production nonce
    /// length defined in Requirement 5.1.
    /// </summary>
    private static Arbitrary<byte[]> Nonce32Arbitrary() =>
        Arb.From(
            Gen.ArrayOf(32, Arb.Generate<byte>()),
            // Shrinker: keep arrays at full 32-byte length to stay valid.
            _ => Seq<byte[]>.Empty);

    /// <summary>
    /// Arbitrary for a non-empty list of distinct 32-byte nonces, up to 10
    /// entries (simulates a small batch written in one service lifetime).
    /// </summary>
    private static Arbitrary<List<byte[]>> NonceBatchArbitrary() =>
        Arb.From(
            from count in Gen.Choose(1, 10)
            from arrays in Gen.ListOf(count, Gen.ArrayOf(32, Arb.Generate<byte>()))
            // Deduplicate by base-64 to avoid the same nonce appearing twice in
            // the batch (which is valid storage-wise but uninteresting here).
            select arrays
                .GroupBy(Convert.ToBase64String)
                .Select(g => g.First())
                .ToList());

    // -----------------------------------------------------------------------
    // Property 1: Single arbitrary nonce survives a simulated restart
    // -----------------------------------------------------------------------

    /// <summary>
    /// For any arbitrary 32-byte nonce array, after writing it to a store
    /// and creating a NEW <see cref="ConsumedNonceStore"/> instance backed by
    /// the same file path and calling Load(), Contains(nonce) returns true.
    /// This simulates a service restart within the 24-hour retention window.
    /// Validates: Requirements 5.7, 13.4
    /// </summary>
    [Property(MaxTest = 100, Arbitrary = new[] { typeof(NonceStorePersistencePropertyTests) })]
    public bool SingleNonce_SurvivesSimulatedRestart(byte[] nonce)
    {
        if (nonce is null || nonce.Length != 32)
            return true; // Precondition not met — skip this sample.

        string path = _fixture.NewStorePath();

        // First store instance (simulates running service).
        var store1 = new ConsumedNonceStore(path);
        store1.Load();
        store1.Append(nonce);

        // Second store instance (simulates service after restart).
        var store2 = new ConsumedNonceStore(path);
        store2.Load();

        return store2.Contains(nonce);
    }

    /// <summary>
    /// Exposes <see cref="Nonce32Arbitrary"/> to FsCheck's Arbitrary
    /// resolution via the class-level Arbitrary attribute on the property.
    /// </summary>
    public static Arbitrary<byte[]> Nonce() => Nonce32Arbitrary();

    // -----------------------------------------------------------------------
    // Property 2: Batch of N nonces — all survive a simulated restart
    // -----------------------------------------------------------------------

    /// <summary>
    /// For any batch of N nonces (N in [1..10]), all written in one store
    /// instance, a new instance loading from the same file contains all N
    /// nonces after Load().
    /// Validates: Requirements 5.7, 13.4
    /// </summary>
    [Property(MaxTest = 100)]
    public Property BatchOfNonces_AllSurviveSimulatedRestart()
    {
        return Prop.ForAll(
            NonceBatchArbitrary(),
            batch =>
            {
                string path = _fixture.NewStorePath();

                // First store instance — write all nonces.
                var store1 = new ConsumedNonceStore(path);
                store1.Load();
                foreach (var nonce in batch)
                    store1.Append(nonce);

                // Second store instance — simulates service restart.
                var store2 = new ConsumedNonceStore(path);
                store2.Load();

                // Every nonce written must be present in the reloaded store.
                return batch.All(nonce => store2.Contains(nonce));
            });
    }

    // -----------------------------------------------------------------------
    // Fact 1: Concrete example — single known nonce survives restart
    // -----------------------------------------------------------------------

    /// <summary>
    /// Appends a known nonce, creates a new store instance backed by the same
    /// file, loads it, and asserts Contains returns true.
    /// </summary>
    [Fact]
    public void NonceAppended_SurvivesSimulatedRestart_ConcreteExample()
    {
        string path = _fixture.NewStorePath();

        // Known nonce — all bytes set to 0xAB for determinism.
        var nonce = new byte[32];
        Array.Fill(nonce, (byte)0xAB);

        // First store instance.
        var store1 = new ConsumedNonceStore(path);
        store1.Load();
        store1.Append(nonce);

        // Simulate restart — new instance, same file.
        var store2 = new ConsumedNonceStore(path);
        store2.Load();

        Assert.True(store2.Contains(nonce),
            "A nonce appended before restart must be present in the reloaded store.");
    }

    // -----------------------------------------------------------------------
    // Fact 2: Fresh nonce is kept within the 24-hour retention window
    // -----------------------------------------------------------------------

    /// <summary>
    /// Appends a fresh nonce (consumed right now) and verifies that a new
    /// store instance loading the same file finds it.  The 24-hour retention
    /// window guarantees that any nonce written during the current session is
    /// always retained across an immediate restart.
    /// Validates: Requirements 5.7, 13.4
    /// </summary>
    [Fact]
    public void NoncePersistence_Within24HourWindow()
    {
        string path = _fixture.NewStorePath();

        // Generate a cryptographically random nonce as production would.
        var nonce = RandomNumberGenerator.GetBytes(32);

        // Write to first store instance.
        var store1 = new ConsumedNonceStore(path);
        store1.Load();
        store1.Append(nonce);

        // New store instance — simulates service process being restarted
        // well within the 24-hour retention window.
        var store2 = new ConsumedNonceStore(path);
        store2.Load();

        Assert.True(store2.Contains(nonce),
            "A nonce consumed within the 24-hour window must survive a service restart.");
    }

    // -----------------------------------------------------------------------
    // Fact 3: Five distinct nonces — all persist across restart
    // -----------------------------------------------------------------------

    /// <summary>
    /// Writes 5 distinct nonces to one store instance, then creates a new
    /// instance backed by the same file, calls Load(), and asserts that all
    /// 5 nonces are found.
    /// Validates: Requirements 5.7, 13.4
    /// </summary>
    [Fact]
    public void MultipleNonces_AllPersistAcrossRestart()
    {
        string path = _fixture.NewStorePath();

        // Generate 5 distinct cryptographically random nonces.
        var nonces = Enumerable.Range(0, 5)
            .Select(_ => RandomNumberGenerator.GetBytes(32))
            .ToList();

        // First store instance — write all five nonces.
        var store1 = new ConsumedNonceStore(path);
        store1.Load();
        foreach (var nonce in nonces)
            store1.Append(nonce);

        // Second store instance — simulates service restart.
        var store2 = new ConsumedNonceStore(path);
        store2.Load();

        // Assert every nonce is present in the reloaded store.
        foreach (var nonce in nonces)
            Assert.True(store2.Contains(nonce),
                $"Nonce {Convert.ToBase64String(nonce)} must persist across a simulated service restart.");
    }
}
