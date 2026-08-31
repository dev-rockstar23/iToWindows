// Feature: pc-unlock
// IPairingHandler — contract for the PC-side QR pairing orchestrator.
// Requirements: 6.1, 6.2, 6.5, 6.6

namespace PCUnlockService.Pairing;

/// <summary>
/// Orchestrates the PC side of the QR pairing flow.
/// </summary>
public interface IPairingHandler
{
    /// <summary>
    /// Starts a new pairing session:
    /// <list type="number">
    ///   <item>Generates a 128-bit <c>pcIdentityToken</c> and a 6-char <c>Pairing_Code</c>.</item>
    ///   <item>Encodes the <see cref="PairingPayload"/> as JSON and renders a QR code.</item>
    ///   <item>Awaits the iPhone's BLE write (public key + Pairing_Code echo).</item>
    ///   <item>Verifies the echoed code.</item>
    ///   <item>On success: persists a <see cref="DeviceRecord"/> and returns <see cref="PairingResult.Success(DeviceRecord)"/>.</item>
    ///   <item>On timeout or mismatch: discards all intermediate state and returns the appropriate result.</item>
    /// </list>
    /// </summary>
    /// <param name="deviceName">User-visible label for the paired device (e.g. "Quinn's iPhone 15").</param>
    /// <param name="ct">
    ///   External cancellation token.  A 120-second internal timeout is also
    ///   enforced regardless of this token (Requirement 6.6).
    /// </param>
    /// <returns>A <see cref="PairingResult"/> describing the outcome.</returns>
    Task<PairingResult> StartPairingAsync(string deviceName, CancellationToken ct = default);
}
