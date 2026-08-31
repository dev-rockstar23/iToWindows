// Feature: pc-unlock
// SessionNonceManager — manages the active unlock session and validates BLE responses
// before forwarding to the CNG Crypto Verifier.
// Requirements: 5.3, 5.4, 5.8, 13.1, 13.2, 13.3

using Microsoft.Extensions.Logging;

namespace PCUnlockService.Session;

/// <summary>
/// Concrete implementation of <see cref="ISessionNonceManager"/>.
/// </summary>
/// <remarks>
/// <para>
/// Maintains at most one active <see cref="UnlockSession"/> in memory.
/// Thread safety: callers are expected to serialise concurrent access; this
/// class does not add locking beyond what is needed for correctness.
/// </para>
/// <para>
/// Validation order (matches design §Verification Flow):
/// <list type="number">
///   <item>No active session → <see cref="ResponseRejectionReason.NoActiveSession"/></item>
///   <item>Session expired  → <see cref="ResponseRejectionReason.Expired"/></item>
///   <item>Session ID mismatch → <see cref="ResponseRejectionReason.SessionMismatch"/></item>
///   <item>Nonce already consumed → <see cref="ResponseRejectionReason.ReplayedNonce"/></item>
///   <item>All pass → <see cref="ResponseValidationResult.Valid"/></item>
/// </list>
/// </para>
/// </remarks>
public sealed class SessionNonceManager : ISessionNonceManager
{
    private readonly IConsumedNonceStore _nonceStore;
    private readonly ILogger<SessionNonceManager> _logger;

    /// <summary>The single in-memory active session; <c>null</c> when no session is running.</summary>
    private UnlockSession? _activeSession;

    /// <summary>
    /// Initialises the manager with the required dependencies.
    /// </summary>
    /// <param name="nonceStore">
    /// Persistent store used to detect replay attempts (Requirement 5.4, 13.1).
    /// </param>
    /// <param name="logger">Logger for security-relevant events (Requirements 8.4, 10.3).</param>
    public SessionNonceManager(IConsumedNonceStore nonceStore, ILogger<SessionNonceManager> logger)
    {
        _nonceStore = nonceStore ?? throw new ArgumentNullException(nameof(nonceStore));
        _logger     = logger     ?? throw new ArgumentNullException(nameof(logger));
    }

    // -----------------------------------------------------------------------
    // ISessionNonceManager
    // -----------------------------------------------------------------------

    /// <inheritdoc/>
    public UnlockSession StartSession(string deviceId)
    {
        _activeSession = ChallengeGenerator.GenerateChallenge(deviceId);
        _logger.LogInformation(
            "Session started: sessionId={SessionId} deviceId={DeviceId} expiresAt={ExpiresAt}",
            _activeSession.SessionId, deviceId, _activeSession.ExpiresAt);
        return _activeSession;
    }

    /// <inheritdoc/>
    public void ClearSession()
    {
        if (_activeSession is not null)
        {
            _logger.LogInformation("Session cleared: sessionId={SessionId}", _activeSession.SessionId);
            _activeSession = null;
        }
    }

    /// <inheritdoc/>
    public ResponseValidationResult ValidateResponse(BleResponse response)
    {
        // ── 1. No active session ─────────────────────────────────────────────
        if (_activeSession is null)
        {
            _logger.LogWarning("Response rejected: NO_ACTIVE_SESSION");
            return ResponseValidationResult.Rejected(ResponseRejectionReason.NoActiveSession);
        }

        // ── 2. Expiry check (Requirement 5.3, 13.2) ─────────────────────────
        long nowSeconds = DateTimeOffset.UtcNow.ToUnixTimeSeconds();
        if (_activeSession.ExpiresAt <= nowSeconds)
        {
            _logger.LogWarning(
                "Response rejected: EXPIRED — sessionId={SessionId} expiresAt={ExpiresAt} now={Now}",
                _activeSession.SessionId, _activeSession.ExpiresAt, nowSeconds);
            return ResponseValidationResult.Rejected(ResponseRejectionReason.Expired);
        }

        // ── 3. Session ID match (Requirement 13.3) ───────────────────────────
        if (_activeSession.SessionId != response.SessionId)
        {
            _logger.LogWarning(
                "Response rejected: SESSION_MISMATCH — expected={Expected} received={Received}",
                _activeSession.SessionId, response.SessionId);
            return ResponseValidationResult.Rejected(ResponseRejectionReason.SessionMismatch);
        }

        // ── 4. Nonce replay check (Requirement 5.4, 13.1) ───────────────────
        if (_nonceStore.Contains(_activeSession.Nonce))
        {
            _logger.LogWarning(
                "Response rejected: REPLAY — sessionId={SessionId} (nonce already consumed)",
                _activeSession.SessionId);
            return ResponseValidationResult.Rejected(ResponseRejectionReason.ReplayedNonce);
        }

        // ── 5. All checks passed — forward to CNG Crypto Verifier ───────────
        _logger.LogInformation(
            "Response pre-validation passed: sessionId={SessionId} — forwarding to CNG Crypto Verifier",
            _activeSession.SessionId);
        return ResponseValidationResult.Valid();
    }
}
