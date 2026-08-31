// Feature: pc-unlock
namespace PCUnlockService.Session;
public sealed class UnlockSession {
    public Guid SessionId { get; init; }
    public byte[] Nonce { get; init; } = Array.Empty<byte>();
    public long ExpiresAt { get; init; }  // Unix epoch seconds UTC
    public string DeviceId { get; init; } = string.Empty;
    public bool IsExpired => DateTimeOffset.UtcNow.ToUnixTimeSeconds() > ExpiresAt;
}
