// Feature: pc-unlock
// IBLEPairingChannel — abstraction over the BLE Pairing characteristic exchange.
// Requirements: 6.3, 6.5

namespace PCUnlockService.Pairing;

/// <summary>
/// Abstracts the BLE pairing characteristic (<c>A1B2C3D4-E5F6-7890-ABCD-EF1234567893</c>)
/// so that <see cref="PairingHandler"/> can be unit-tested without real BLE hardware.
/// </summary>
public interface IBLEPairingChannel
{
    /// <summary>
    /// Waits for the iPhone to write a <see cref="PairingRequest"/> to the
    /// BLE Pairing characteristic.
    /// </summary>
    /// <param name="ct">
    ///   Cancellation token; typically linked to the 120-second pairing timeout.
    /// </param>
    /// <returns>
    ///   The <see cref="PairingRequest"/> written by the iPhone, or <c>null</c>
    ///   if the operation was cancelled before any write was received.
    /// </returns>
    Task<PairingRequest?> AwaitPairingRequestAsync(CancellationToken ct);

    /// <summary>
    /// Sends the <c>PairingComplete</c> acknowledgement notification to the
    /// iPhone over the BLE Pairing characteristic.
    /// </summary>
    /// <param name="ct">Cancellation token.</param>
    Task SendPairingCompleteAsync(CancellationToken ct);
}
