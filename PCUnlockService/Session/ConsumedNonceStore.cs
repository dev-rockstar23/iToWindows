// Feature: pc-unlock
// ConsumedNonceStore — DPAPI-encrypted, atomically-written nonce store.
// Requirements: 5.5, 5.7, 13.4, 13.5

using System.Security.Cryptography;
using System.Text.Json;

namespace PCUnlockService.Session;

/// <summary>
/// Implements <see cref="IConsumedNonceStore"/> using a DPAPI-encrypted JSON
/// file at <c>%APPDATA%\PCUnlock\nonces.dat</c>.
/// </summary>
/// <remarks>
/// <para>
/// Thread safety: this class is not thread-safe on its own; callers must
/// serialise concurrent <see cref="Append"/> calls if needed.
/// </para>
/// <para>
/// Atomic write: data is first written to a temp file in the same directory
/// and then moved over the target file with <see cref="File.Move"/> using
/// <c>overwrite: true</c>, which on Windows maps to
/// <c>MoveFileEx(MOVEFILE_REPLACE_EXISTING)</c>.
/// </para>
/// </remarks>
public sealed class ConsumedNonceStore : IConsumedNonceStore
{
    // -----------------------------------------------------------------------
    // Constants
    // -----------------------------------------------------------------------

    /// <summary>Entries older than this window are pruned on every write.</summary>
    private static readonly TimeSpan RetentionWindow = TimeSpan.FromHours(24);

    private static readonly JsonSerializerOptions _jsonOptions = new()
    {
        WriteIndented = false,
        PropertyNamingPolicy = JsonNamingPolicy.CamelCase,
    };

    // -----------------------------------------------------------------------
    // State
    // -----------------------------------------------------------------------

    /// <summary>File path of the backing DPAPI-encrypted store.</summary>
    private readonly string _filePath;

    /// <summary>
    /// In-memory set of base-64-encoded nonces for O(1) lookup.
    /// Populated by <see cref="Load"/> and kept in sync by <see cref="Append"/>.
    /// </summary>
    private readonly HashSet<string> _loadedNonces = new(StringComparer.Ordinal);

    /// <summary>
    /// Working copy of the entries list; kept in sync with <see cref="_loadedNonces"/>.
    /// </summary>
    private readonly List<NonceEntry> _entries = new();

    // -----------------------------------------------------------------------
    // Construction
    // -----------------------------------------------------------------------

    /// <summary>
    /// Initialises the store with the default file path
    /// <c>%APPDATA%\PCUnlock\nonces.dat</c>.
    /// </summary>
    public ConsumedNonceStore()
        : this(DefaultFilePath())
    {
    }

    /// <summary>
    /// Initialises the store with a custom file path (useful for tests).
    /// </summary>
    /// <param name="filePath">
    /// Absolute path to the encrypted nonce store file.
    /// The directory is created automatically if it does not exist.
    /// </param>
    public ConsumedNonceStore(string filePath)
    {
        if (string.IsNullOrWhiteSpace(filePath))
            throw new ArgumentException("File path must not be null or whitespace.", nameof(filePath));

        _filePath = filePath;
    }

    // -----------------------------------------------------------------------
    // IConsumedNonceStore
    // -----------------------------------------------------------------------

    /// <inheritdoc/>
    public void Load()
    {
        _loadedNonces.Clear();
        _entries.Clear();

        if (!File.Exists(_filePath))
            return;

        byte[] encryptedBytes;
        try
        {
            encryptedBytes = File.ReadAllBytes(_filePath);
        }
        catch (IOException)
        {
            // If the file cannot be read, start with an empty store rather
            // than blocking service startup.
            return;
        }

        byte[] jsonBytes;
        try
        {
            jsonBytes = ProtectedData.Unprotect(
                encryptedBytes,
                optionalEntropy: null,
                scope: DataProtectionScope.CurrentUser);
        }
        catch (CryptographicException)
        {
            // Decryption failure (e.g. running as a different user or corrupt
            // data) — start empty to avoid blocking service startup.
            return;
        }

        NonceStoreData? data;
        try
        {
            data = JsonSerializer.Deserialize<NonceStoreData>(jsonBytes, _jsonOptions);
        }
        catch (JsonException)
        {
            // Parse failure — start empty.
            return;
        }

        if (data is null)
            return;

        var cutoff = DateTimeOffset.UtcNow - RetentionWindow;

        foreach (var entry in data.Entries)
        {
            // Skip entries that are already beyond the retention window.
            if (entry.ConsumedAt < cutoff)
                continue;

            if (string.IsNullOrEmpty(entry.Nonce))
                continue;

            _entries.Add(entry);
            _loadedNonces.Add(entry.Nonce);
        }
    }

    /// <inheritdoc/>
    public bool Contains(byte[] nonce)
    {
        if (nonce is null || nonce.Length == 0)
            return false;

        return _loadedNonces.Contains(Convert.ToBase64String(nonce));
    }

    /// <inheritdoc/>
    public void Append(byte[] nonce)
    {
        if (nonce is null || nonce.Length == 0)
            throw new ArgumentException("Nonce must not be null or empty.", nameof(nonce));

        var b64 = Convert.ToBase64String(nonce);
        var entry = new NonceEntry
        {
            Nonce       = b64,
            ConsumedAt  = DateTimeOffset.UtcNow,
        };

        // Build updated entries list, pruning stale entries.
        var cutoff = DateTimeOffset.UtcNow - RetentionWindow;

        var pruned = new List<NonceEntry>(_entries.Count + 1);
        foreach (var e in _entries)
        {
            if (e.ConsumedAt >= cutoff)
                pruned.Add(e);
        }
        pruned.Add(entry);

        var storeData = new NonceStoreData { Entries = pruned };

        // Serialise → DPAPI-encrypt → atomic write.
        byte[] jsonBytes = JsonSerializer.SerializeToUtf8Bytes(storeData, _jsonOptions);
        byte[] encrypted = ProtectedData.Protect(
            jsonBytes,
            optionalEntropy: null,
            scope: DataProtectionScope.CurrentUser);

        AtomicWrite(encrypted);

        // Only update the in-memory state after the file write succeeds, so
        // that a write failure leaves the store in a consistent state.
        _entries.Clear();
        foreach (var e in pruned)
            _entries.Add(e);

        _loadedNonces.Clear();
        foreach (var e in pruned)
            _loadedNonces.Add(e.Nonce);
    }

    // -----------------------------------------------------------------------
    // Private helpers
    // -----------------------------------------------------------------------

    /// <summary>
    /// Writes <paramref name="data"/> to a temp file in the same directory as
    /// <see cref="_filePath"/>, then atomically moves it over the target via
    /// <see cref="File.Move"/> with <c>overwrite: true</c>.
    /// </summary>
    private void AtomicWrite(byte[] data)
    {
        string? directory = Path.GetDirectoryName(_filePath);
        if (!string.IsNullOrEmpty(directory))
            Directory.CreateDirectory(directory);

        // Create temp file in the same directory so the rename is on the same
        // volume, guaranteeing an atomic MoveFileEx operation.
        string tempPath = Path.Combine(
            directory ?? Path.GetTempPath(),
            Path.GetRandomFileName());

        try
        {
            File.WriteAllBytes(tempPath, data);
            // File.Move with overwrite:true → MoveFileEx(MOVEFILE_REPLACE_EXISTING)
            File.Move(tempPath, _filePath, overwrite: true);
        }
        catch
        {
            // Clean up the temp file on failure; let the exception propagate.
            try { File.Delete(tempPath); } catch { /* best-effort */ }
            throw;
        }
    }

    /// <summary>Returns the default file path for the nonce store.</summary>
    private static string DefaultFilePath() =>
        Path.Combine(
            Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData),
            "PCUnlock",
            "nonces.dat");
}
