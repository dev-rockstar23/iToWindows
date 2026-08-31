// Feature: pc-unlock
// DeviceRecord — persisted record for a paired iPhone in the Device Registry.
// Requirements: 6.5, 9.1, 9.2, 9.4

namespace PCUnlockService.Pairing;

/// <summary>
/// Represents a paired iPhone stored in the Device Registry.
/// </summary>
/// <remarks>
/// Serialised as part of a JSON array encrypted with DPAPI (per-user scope)
/// into <c>%APPDATA%\PCUnlock\devices.dat</c>.
/// </remarks>
public sealed record DeviceRecord
{
    /// <summary>Stable, unique identifier assigned at pairing time.</summary>
    public Guid DeviceId { get; init; }

    /// <summary>User-visible label (e.g. "Quinn's iPhone 15").</summary>
    public string DeviceName { get; init; } = string.Empty;

    /// <summary>
    /// SubjectPublicKeyInfo DER encoding of the iPhone's P-256 public key,
    /// registered during pairing.
    /// </summary>
    public byte[] PublicKeyDER { get; init; } = Array.Empty<byte>();

    /// <summary>ISO-8601 UTC timestamp of when this device was paired.</summary>
    public DateTimeOffset PairedAt { get; init; }

    /// <summary>
    /// ISO-8601 UTC timestamp of the last successful unlock with this device.
    /// <c>null</c> if the device has never been used for an unlock.
    /// </summary>
    public DateTimeOffset? LastUsedAt { get; init; }

    /// <summary>
    /// The 128-bit (16-byte) PC identity token that was embedded in the
    /// pairing QR code and echoed back by the iPhone.
    /// </summary>
    public byte[] PcIdentityToken { get; init; } = Array.Empty<byte>();
}
