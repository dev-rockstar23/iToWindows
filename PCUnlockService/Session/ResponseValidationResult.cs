// Feature: pc-unlock
// ResponseValidationResult — result of Session/Nonce Manager response validation.
// Requirements: 5.3, 5.4, 5.8, 13.1, 13.2, 13.3

namespace PCUnlockService.Session;

/// <summary>
/// Enumerates the reasons a <see cref="BleResponse"/> may be rejected during
/// pre-signature validation by the <see cref="SessionNonceManager"/>.
/// </summary>
public enum ResponseRejectionReason
{
    /// <summary>No rejection; the response passed all validation checks.</summary>
    None,

    /// <summary>The active session's <c>expiresAt</c> timestamp is in the past.</summary>
    Expired,

    /// <summary>The session nonce is already present in the <see cref="IConsumedNonceStore"/>.</summary>
    ReplayedNonce,

    /// <summary>The <c>sessionId</c> in the response does not match the active session.</summary>
    SessionMismatch,

    /// <summary>There is no active unlock session when the response arrived.</summary>
    NoActiveSession,
}

/// <summary>
/// Represents the outcome of <see cref="ISessionNonceManager.ValidateResponse"/>.
/// </summary>
public sealed class ResponseValidationResult
{
    /// <summary><c>true</c> when all pre-signature checks passed.</summary>
    public bool IsValid { get; init; }

    /// <summary>
    /// The rejection reason when <see cref="IsValid"/> is <c>false</c>;
    /// <see cref="ResponseRejectionReason.None"/> when valid.
    /// </summary>
    public ResponseRejectionReason Reason { get; init; }

    /// <summary>Returns a successful validation result.</summary>
    public static ResponseValidationResult Valid() =>
        new() { IsValid = true, Reason = ResponseRejectionReason.None };

    /// <summary>Returns a rejected validation result with the given reason.</summary>
    /// <param name="reason">Why the response was rejected.</param>
    public static ResponseValidationResult Rejected(ResponseRejectionReason reason) =>
        new() { IsValid = false, Reason = reason };
}
