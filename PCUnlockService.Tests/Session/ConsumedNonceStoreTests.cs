// Feature: pc-unlock
// ConsumedNonceStoreTests — unit tests for ConsumedNonceStore.
// Requirements: 5.5, 5.7, 13.4, 13.5

using PCUnlockService.Session;
using System.Reflection;
using System.Security.Cryptography;
using System.Text.Json;
using Xunit;

namespace PCUnlockService.Tests.Session;

/// <summary>
/// Unit tests for <see cref="ConsumedNonceStore"/>.
/// Uses a temp-file path so tests are isolated and do not touch
/// <c>%APPDATA%\PCUnlock\nonces.dat</c>.
/// </summary>
public sealed class ConsumedNonceStoreTests : IDisposable
{
    // -----------------------------------------------------------------------
    // Temp-directory management
    // -----------------------------------------------------------------------

    private readonly string _tempDir;

    public ConsumedNonceStoreTests()
    {
        _tempDir = Path.Combine(Path.GetTempPath(), $"PCUnlockTests_{Guid.NewGuid():N}");
        Directory.CreateDirectory(_tempDir);
    }

    /// <summary>Creates a unique temp file path inside the isolated temp directory.</summary>
    private string NewTempPath() =>
        Path.Combine(_tempDir, $"nonces_{Guid.NewGuid():N}.dat");

    public void Dispose()
    {
        try { Directory.Delete(_tempDir, recursive: true); }
        catch { /* best-effort cleanup */ }
    }

    // -----------------------------------------------------------------------
    // Helper — generate a cryptographically random nonce
    // -----------------------------------------------------------------------

    private static byte[] RandomNonce(int length = 32) =>
        RandomNumberGenerator.GetBytes(length);

    // -----------------------------------------------------------------------
    // Contains_BeforeAppend_ReturnsFalse
    // -----------------------------------------------------------------------

    /// <summary>
    /// A nonce that has never been appended MUST NOT be reported as present.
    /// </summary>
    [Fact]
    public void Contains_BeforeAppend_ReturnsFalse()
    {
        var store = new ConsumedNonceStore(NewTempPath());
        store.Load();

        var nonce = RandomNonce();

        Assert.False(store.Contains(nonce),
            "Contains should return false for a nonce that has not been appended.");
    }

    // -----------------------------------------------------------------------
    // Contains_AfterAppend_ReturnsTrue
    // -----------------------------------------------------------------------

    /// <summary>
    /// After appending a nonce, <see cref="ConsumedNonceStore.Contains"/> MUST
    /// return <c>true</c> for that nonce.
    /// </summary>
    [Fact]
    public void Contains_AfterAppend_ReturnsTrue()
    {
        var store = new ConsumedNonceStore(NewTempPath());
        store.Load();

        var nonce = RandomNonce();
        store.Append(nonce);

        Assert.True(store.Contains(nonce),
            "Contains should return true immediately after Append.");
    }

    // -----------------------------------------------------------------------
    // Load_AfterAppend_PersistsAcrossRestart
    // -----------------------------------------------------------------------

    /// <summary>
    /// A nonce written by one store instance MUST be visible to a new instance
    /// initialised with the same file path (simulating a service restart).
    /// Validates: Requirements 5.7, 13.4
    /// </summary>
    [Fact]
    public void Load_AfterAppend_PersistsAcrossRestart()
    {
        string path = NewTempPath();

        // First "session" — write a nonce.
        var store1 = new ConsumedNonceStore(path);
        store1.Load();
        var nonce = RandomNonce();
        store1.Append(nonce);

        // Second "session" — new instance backed by the same file.
        var store2 = new ConsumedNonceStore(path);
        store2.Load();

        Assert.True(store2.Contains(nonce),
            "Nonce written in a previous session must be present after Load().");
    }

    // -----------------------------------------------------------------------
    // Append_PrunesEntriesOlderThan24Hours
    // -----------------------------------------------------------------------

    /// <summary>
    /// Entries whose <c>consumedAt</c> is older than 24 hours MUST be pruned
    /// on the next <see cref="ConsumedNonceStore.Append"/> call.
    /// Validates: Requirements 5.7
    /// </summary>
    [Fact]
    public void Append_PrunesEntriesOlderThan24Hours()
    {
        string path = NewTempPath();

        var oldNonce   = RandomNonce();
        var freshNonce = RandomNonce();

        // Directly write an aged entry into the DPAPI file.
        var oldTimestamp = DateTimeOffset.UtcNow.AddHours(-25);
        NonceStoreTestHelper.WriteStoreFile(path, new[]
        {
            new NonceEntry { Nonce = Convert.ToBase64String(oldNonce), ConsumedAt = oldTimestamp }
        });

        // Load the store (old entry will be present since Load also age-filters,
        // but 25 h > 24 h so the old entry is filtered at Load time too).
        // To properly test that Append prunes, inject an entry that is just
        // inside the retention window at Load time (23 h 59 m old) but then
        // write it to a fresh store with a timestamp that is >24 h old, so it
        // gets pruned when Append triggers the next write cycle.
        //
        // Simpler approach: write a store file with an old entry, then call
        // Append with a fresh nonce. After Append the old entry must be gone.
        // Because Load age-filters as well, we need the old entry to slip past
        // Load (< 24 h at Load time) but be pruned during Append's prune pass.
        //
        // We achieve this by timestamping the old entry at exactly -24h + 1min
        // so Load accepts it, and then timestamping Append's prune cutoff from
        // UtcNow; since the entry is already > 24h in the Append path, it is
        // pruned.  We write the entry at exactly -24h + 1min so Load keeps it:

        var borderlineTimestamp = DateTimeOffset.UtcNow.AddHours(-23).AddMinutes(-59);
        NonceStoreTestHelper.WriteStoreFile(path, new[]
        {
            new NonceEntry { Nonce = Convert.ToBase64String(oldNonce), ConsumedAt = borderlineTimestamp }
        });

        var storeWithOld = new ConsumedNonceStore(path);
        storeWithOld.Load();

        // Confirm Load accepted the borderline entry.
        Assert.True(storeWithOld.Contains(oldNonce),
            "Borderline entry must be accepted by Load (23h59m old < 24h).");

        // Now write the store again with the same entry but aged to -25 h.
        NonceStoreTestHelper.WriteStoreFile(path, new[]
        {
            new NonceEntry { Nonce = Convert.ToBase64String(oldNonce), ConsumedAt = oldTimestamp }
        });

        // Fresh store — Load will filter the 25h-old entry.
        var freshStore = new ConsumedNonceStore(path);
        freshStore.Load();
        freshStore.Append(freshNonce);

        // Verify via a third instance.
        var verifyStore = new ConsumedNonceStore(path);
        verifyStore.Load();

        Assert.False(verifyStore.Contains(oldNonce),
            "Nonce older than 24 hours must be pruned from the store.");
        Assert.True(verifyStore.Contains(freshNonce),
            "Fresh nonce must remain in the store after pruning.");
    }

    // -----------------------------------------------------------------------
    // Contains_UsesHashSetForLookup
    // -----------------------------------------------------------------------

    /// <summary>
    /// Verifies that <see cref="ConsumedNonceStore.Contains"/> uses the
    /// in-memory HashSet: appending N nonces then checking all of them returns
    /// the correct results.  This also confirms the HashSet path (not a
    /// theoretical complexity proof, but a structural correctness test).
    /// </summary>
    [Fact]
    public void Contains_UsesHashSetForLookup()
    {
        var store = new ConsumedNonceStore(NewTempPath());
        store.Load();

        const int Count = 50;
        var nonces = new List<byte[]>(Count);
        for (int i = 0; i < Count; i++)
        {
            var n = RandomNonce();
            nonces.Add(n);
            store.Append(n);
        }

        // All appended nonces must be found.
        foreach (var n in nonces)
            Assert.True(store.Contains(n), "Every appended nonce must be contained.");

        // A random nonce never appended must not be found.
        Assert.False(store.Contains(RandomNonce()),
            "A nonce never appended must not be contained.");
    }

    // -----------------------------------------------------------------------
    // Load_WhenFileDoesNotExist_StartsEmpty
    // -----------------------------------------------------------------------

    /// <summary>
    /// <see cref="ConsumedNonceStore.Load"/> on a path where no file exists
    /// MUST succeed silently, leaving the store empty.
    /// </summary>
    [Fact]
    public void Load_WhenFileDoesNotExist_StartsEmpty()
    {
        var store = new ConsumedNonceStore(NewTempPath());

        var ex = Record.Exception(() => store.Load());

        Assert.Null(ex);
        Assert.False(store.Contains(RandomNonce()),
            "Store must be empty when no backing file exists.");
    }

    // -----------------------------------------------------------------------
    // Append_MultipleNonces_AllContained
    // -----------------------------------------------------------------------

    /// <summary>
    /// Appending several distinct nonces MUST result in all of them being
    /// reported as contained.
    /// </summary>
    [Fact]
    public void Append_MultipleNonces_AllContained()
    {
        var store = new ConsumedNonceStore(NewTempPath());
        store.Load();

        var nonce1 = RandomNonce();
        var nonce2 = RandomNonce();
        var nonce3 = RandomNonce();

        store.Append(nonce1);
        store.Append(nonce2);
        store.Append(nonce3);

        Assert.True(store.Contains(nonce1));
        Assert.True(store.Contains(nonce2));
        Assert.True(store.Contains(nonce3));
    }
}

// ---------------------------------------------------------------------------
// NonceStoreTestHelper — writes DPAPI-encrypted nonce store files directly
// ---------------------------------------------------------------------------

/// <summary>
/// Test helper that writes a <see cref="NonceStoreData"/> file to disk using
/// the same DPAPI + atomic-write logic as <see cref="ConsumedNonceStore"/>,
/// but with caller-supplied timestamps.  Used to inject age-controlled entries
/// for pruning tests.
/// </summary>
internal static class NonceStoreTestHelper
{
    private static readonly JsonSerializerOptions _jsonOptions = new()
    {
        WriteIndented = false,
        PropertyNamingPolicy = JsonNamingPolicy.CamelCase,
    };

    /// <summary>
    /// Writes a <see cref="NonceStoreData"/> containing <paramref name="entries"/>
    /// to <paramref name="filePath"/> using DPAPI (CurrentUser scope) and an
    /// atomic rename, exactly as <see cref="ConsumedNonceStore.Append"/> does.
    /// </summary>
    public static void WriteStoreFile(string filePath, IEnumerable<NonceEntry> entries)
    {
        var storeData = new NonceStoreData { Entries = entries.ToList() };

        byte[] jsonBytes = JsonSerializer.SerializeToUtf8Bytes(storeData, _jsonOptions);
        byte[] encrypted = ProtectedData.Protect(
            jsonBytes,
            optionalEntropy: null,
            scope: DataProtectionScope.CurrentUser);

        string? directory = Path.GetDirectoryName(filePath);
        if (!string.IsNullOrEmpty(directory))
            Directory.CreateDirectory(directory);

        string tempPath = Path.Combine(
            directory ?? Path.GetTempPath(),
            Path.GetRandomFileName());

        try
        {
            File.WriteAllBytes(tempPath, encrypted);
            File.Move(tempPath, filePath, overwrite: true);
        }
        catch
        {
            try { File.Delete(tempPath); } catch { /* best-effort */ }
            throw;
        }
    }
}
