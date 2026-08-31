// Feature: pc-unlock
// NonceEntry / NonceStoreData — data models for the ConsumedNonceStore.
// Requirements: 5.5, 5.7, 13.4, 13.5

using System.Text.Json.Serialization;

namespace PCUnlockService.Session;

/// <summary>
/// A single entry in the consumed-nonce store.
/// </summary>
public sealed record NonceEntry
{
    /// <summary>Base-64-encoded nonce bytes.</summary>
    [JsonPropertyName("nonce")]
    public string Nonce { get; init; } = string.Empty;

    /// <summary>UTC timestamp at which this nonce was consumed.</summary>
    [JsonPropertyName("consumedAt")]
    public DateTimeOffset ConsumedAt { get; init; }
}

/// <summary>
/// Root object that is JSON-serialised and then DPAPI-encrypted into
/// <c>%APPDATA%\PCUnlock\nonces.dat</c>.
/// </summary>
public sealed class NonceStoreData
{
    /// <summary>Format version — always 1 for this implementation.</summary>
    [JsonPropertyName("version")]
    public int Version { get; init; } = 1;

    /// <summary>All currently tracked (non-pruned) consumed nonce entries.</summary>
    [JsonPropertyName("entries")]
    public List<NonceEntry> Entries { get; init; } = new();
}
