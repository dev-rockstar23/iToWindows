// Feature: pc-unlock
// IConsumedNonceStore — interface for the persistent replay-prevention nonce store.
// Requirements: 5.5, 5.7, 13.4, 13.5

namespace PCUnlockService.Session;

/// <summary>
/// Persistent store of consumed nonces that survives service restarts.
/// Used to enforce replay-attack prevention (Requirements 5.4, 5.7, 13.1, 13.4).
/// </summary>
/// <remarks>
/// The backing file is DPAPI-encrypted and written atomically.
/// Entries are pruned after 24 hours on every write.
/// An in-memory HashSet provides O(1) lookup via <see cref="Contains"/>.
/// </remarks>
public interface IConsumedNonceStore
{
    /// <summary>
    /// Loads the nonce store from disk on service startup.
    /// Decrypts the file, parses the JSON, and populates the in-memory set.
    /// If the file does not exist the store starts empty with no error.
    /// </summary>
    void Load();

    /// <summary>
    /// Returns <c>true</c> if <paramref name="nonce"/> is already present in
    /// the in-memory set; <c>false</c> otherwise.  O(1) lookup.
    /// </summary>
    /// <param name="nonce">Raw nonce bytes to test.</param>
    bool Contains(byte[] nonce);

    /// <summary>
    /// Adds <paramref name="nonce"/> to the store, prunes entries older than
    /// 24 hours, re-encrypts the data, and atomically replaces the backing file.
    /// The in-memory set is updated only after the file write succeeds.
    /// </summary>
    /// <param name="nonce">Raw nonce bytes to consume.</param>
    void Append(byte[] nonce);
}
