// Feature: pc-unlock
// BleResponse — the Response struct received from the iPhone over BLE transport.
// Requirements: 5.3, 5.4, 5.8, 13.1, 13.2, 13.3

namespace PCUnlockService.Session;

/// <summary>
/// Represents the response packet received from the PCUnlock_App over BLE.
/// </summary>
/// <remarks>
/// Wire layout (before deserialization):
/// [version:1][sessionId:16][deviceId:16][signatureDER:variable]
/// The DER-encoded ECDSA-P256 signature is typically 70–72 bytes.
/// </remarks>
public sealed record BleResponse
{
    /// <summary>Protocol version byte (currently 1).</summary>
    public byte Version { get; init; }

    /// <summary>Session ID echoed from the Challenge that was signed.</summary>
    public Guid SessionId { get; init; }

    /// <summary>Stable device identifier of the paired iPhone.</summary>
    public Guid DeviceId { get; init; }

    /// <summary>DER-encoded ECDSA-P256 signature over SHA-256(canonicalEncode(challenge)).</summary>
    public byte[] SignatureDER { get; init; } = Array.Empty<byte>();
}
