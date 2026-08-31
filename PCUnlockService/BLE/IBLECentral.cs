// Feature: pc-unlock
// IBLECentral — interface for the Windows BLE Central role.
// Abstracted for testability (mock/stub in unit tests).
// Requirements: 4.1, 4.3, 4.6

namespace PCUnlockService.BLE;

/// <summary>
/// Contract for the BLE Central component that scans for and connects to a
/// PCUnlock iOS peripheral, performs the Challenge/Response exchange, and
/// returns a typed <see cref="BLESessionResult"/>.
/// </summary>
public interface IBLECentral
{
    /// <summary>
    /// Starts a BLE scan, connects to the first peripheral advertising the
    /// PCUnlock GATT service UUID, performs the three-step exchange:
    /// <list type="number">
    ///   <item>Read DeviceAdvData characteristic to obtain <c>deviceId</c>.</item>
    ///   <item>Write <paramref name="challengeBytes"/> to the Challenge characteristic.</item>
    ///   <item>Await a Notify on the Response characteristic.</item>
    /// </list>
    /// The entire session is bounded by a 15-second timeout
    /// (Requirement 4.6).  On timeout the method returns
    /// <see cref="BLESessionStatus.Timeout"/> and does NOT produce an unlock
    /// signal.
    /// </summary>
    /// <param name="challengeBytes">
    ///   The 57-byte canonical-encoded Challenge to write to the peripheral.
    /// </param>
    /// <param name="cancellationToken">
    ///   External cancellation token (e.g. from the Named Pipe server when the
    ///   CP disconnects).  The 15-second session timeout is enforced internally
    ///   using an additional <see cref="CancellationTokenSource"/> linked to
    ///   this token.
    /// </param>
    /// <returns>
    ///   A <see cref="BLESessionResult"/> describing the outcome of the attempt.
    /// </returns>
    Task<BLESessionResult> RunSessionAsync(
        byte[] challengeBytes,
        CancellationToken cancellationToken = default);

    /// <summary>
    /// Stops any ongoing scan or active session immediately.
    /// Safe to call even if no session is running.
    /// </summary>
    void StopScan();
}
