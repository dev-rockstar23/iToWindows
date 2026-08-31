// Feature: pc-unlock
// VerificationResult — typed outcome for ECDSA-P256 signature verification.
// Requirements: 3.2, 3.3, 3.6, 5.6
namespace PCUnlockService.Crypto;

/// <summary>
/// Discriminated outcome returned by <see cref="ICNGCryptoVerifier.Verify"/>.
/// </summary>
public enum VerificationOutcome
{
    /// <summary>Signature verified successfully.</summary>
    Success,

    /// <summary>Signature bytes are structurally valid but do not verify against the key + digest.</summary>
    BadSignature,

    /// <summary>The supplied public key bytes could not be imported as an ECDSA-P256 SPKI key.</summary>
    InvalidPublicKey,

    /// <summary>The supplied signature bytes are not a valid DER-encoded ECDSA signature.</summary>
    InvalidSignatureFormat,
}

/// <summary>
/// Represents the result of a single <see cref="ICNGCryptoVerifier.Verify"/> call.
/// </summary>
public sealed class VerificationResult
{
    /// <summary>The outcome of the verification attempt.</summary>
    public VerificationOutcome Outcome { get; init; }

    /// <summary>
    /// Optional diagnostic message from the underlying cryptographic exception.
    /// <c>null</c> when <see cref="Outcome"/> is <see cref="VerificationOutcome.Success"/>.
    /// </summary>
    public string? ErrorMessage { get; init; }

    // Construction is private; callers use the factory methods below.
    private VerificationResult() { }

    /// <summary>Creates a successful result.</summary>
    public static VerificationResult Success() =>
        new() { Outcome = VerificationOutcome.Success };

    /// <summary>Creates a failure result with the given <paramref name="reason"/> and optional message.</summary>
    public static VerificationResult Fail(VerificationOutcome reason, string? msg = null) =>
        new() { Outcome = reason, ErrorMessage = msg };
}
