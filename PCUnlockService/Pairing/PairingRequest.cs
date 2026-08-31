// Feature: pc-unlock
// PairingRequest — represents the BLE write sent by the iPhone to complete pairing.
// Requirements: 6.3, 6.5

namespace PCUnlockService.Pairing;

/// <summary>
/// The data written by the iPhone to the BLE Pairing characteristic
/// (<c>A1B2C3D4-E5F6-7890-ABCD-EF1234567893</c>) once the user has confirmed
/// the Pairing_Code on the iPhone side.
/// </summary>
/// <remarks>
/// The iPhone transmits:
/// <list type="bullet">
///   <item><see cref="PublicKeyDER"/> — the iPhone's ECC P-256 public key in SPKI DER format.</item>
///   <item><see cref="PairingCodeEcho"/> — the Pairing_Code originally displayed to the user, echoed back for verification.</item>
/// </list>
/// </remarks>
public sealed record PairingRequest
{
    /// <summary>iPhone's ECC P-256 public key serialised as SPKI DER bytes (~91 bytes).</summary>
    public byte[] PublicKeyDER { get; init; } = Array.Empty<byte>();

    /// <summary>
    /// The 6-character alphanumeric Pairing_Code echoed back from the iPhone
    /// for out-of-band code verification.
    /// </summary>
    public string PairingCodeEcho { get; init; } = string.Empty;
}
