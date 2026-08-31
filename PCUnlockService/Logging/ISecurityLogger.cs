// Feature: pc-unlock
// ISecurityLogger — contract for structured Windows Event Log security logging.
// Requirements: 8.4, 8.5, 10.1, 10.2, 10.3, 10.4, 10.5

namespace PCUnlockService.Logging;

/// <summary>
/// Logs security-relevant events to the Windows Application Event Log.
/// Implementations must NEVER include private key bytes, raw nonce values,
/// biometric data, passwords, PINs, or ECDSA signature bytes (Requirement 10.4).
/// </summary>
public interface ISecurityLogger
{
    /// <summary>
    /// Logs an unlock attempt event (Requirement 10.1).
    /// </summary>
    /// <param name="deviceId">Non-secret paired device identifier.</param>
    /// <param name="outcome">Success or failure outcome string.</param>
    /// <param name="failureReason">Failure reason code, or <c>null</c> on success.</param>
    void LogUnlockAttempt(string deviceId, string outcome, string? failureReason = null);

    /// <summary>
    /// Logs a pairing event (Requirement 10.2).
    /// </summary>
    /// <param name="deviceId">Non-secret device identifier.</param>
    /// <param name="outcome">Outcome string (e.g. "success", "timeout", "mismatch").</param>
    void LogPairingEvent(string deviceId, string outcome);

    /// <summary>
    /// Logs a nonce rejection / replay attempt (Requirement 10.3).
    /// </summary>
    /// <param name="sessionId">Session identifier (not the raw nonce).</param>
    /// <param name="rejectionReason">Reason code (e.g. "REPLAY", "EXPIRED").</param>
    void LogNonceRejection(string sessionId, string rejectionReason);
}
