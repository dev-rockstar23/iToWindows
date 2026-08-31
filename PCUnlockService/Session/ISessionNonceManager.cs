// Feature: pc-unlock
// ISessionNonceManager — contract for the Session/Nonce Manager component.
// Requirements: 5.1, 5.2, 5.3, 5.4, 5.8, 13.1, 13.2, 13.3

namespace PCUnlockService.Session;

/// <summary>
/// Manages the single active <see cref="UnlockSession"/> and performs
/// pre-signature response validation (expiry, nonce replay, session ID match).
/// </summary>
public interface ISessionNonceManager
{
    /// <summary>
    /// Starts a new unlock session for the given device: generates a fresh
    /// challenge (nonce, sessionId, expiresAt) and stores it as the active session.
    /// Any previous active session is replaced.
    /// </summary>
    /// <param name="deviceId">Stable identifier of the paired device initiating unlock.</param>
    /// <returns>The newly created <see cref="UnlockSession"/>.</returns>
    UnlockSession StartSession(string deviceId);

    /// <summary>Clears the active session (called on session end, timeout, or service stop).</summary>
    void ClearSession();

    /// <summary>
    /// Validates a received <see cref="BleResponse"/> against the active session:
    /// checks expiry, nonce replay, and session ID match.
    /// Does NOT verify the cryptographic signature — that is delegated to the CNG Crypto Verifier.
    /// </summary>
    /// <param name="response">The response received from the iPhone over BLE.</param>
    /// <returns>
    /// <see cref="ResponseValidationResult.Valid"/> when all checks pass;
    /// <see cref="ResponseValidationResult.Rejected"/> with the appropriate
    /// <see cref="ResponseRejectionReason"/> otherwise.
    /// </returns>
    ResponseValidationResult ValidateResponse(BleResponse response);
}
