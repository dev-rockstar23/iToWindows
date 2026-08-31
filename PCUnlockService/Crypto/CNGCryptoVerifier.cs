// Feature: pc-unlock — uses System.Security.Cryptography (wraps CNG on Windows).
// Implements ECDSA-P256-SHA256 signature verification against a SPKI DER public key.
// Requirements: 3.2, 3.3, 3.6, 5.6
using System.Security.Cryptography;

namespace PCUnlockService.Crypto;

/// <summary>
/// Production implementation of <see cref="ICNGCryptoVerifier"/> using
/// <see cref="ECDsa"/> (backed by CNG on Windows).
/// </summary>
/// <remarks>
/// <para>
/// Algorithm: ECDSA-P256 / SHA-256.
/// Signature encoding: RFC 3279 DER SEQUENCE (two INTEGERs r and s).
/// Public key format: SubjectPublicKeyInfo (SPKI) DER (~91 bytes).
/// </para>
/// <para>
/// No custom cryptographic primitives are used — all operations are
/// delegated to <c>System.Security.Cryptography</c> APIs (Requirement 3.3).
/// </para>
/// </remarks>
public sealed class CNGCryptoVerifier : ICNGCryptoVerifier
{
    /// <inheritdoc/>
    public VerificationResult Verify(
        byte[] publicKeySpkiDer,
        byte[] challengeCanonical,
        byte[] signatureDer)
    {
        // ── 1. Import public key from SPKI DER (Requirement 3.2) ────────────
        ECDsa ecdsa;
        try
        {
            ecdsa = ECDsa.Create(ECCurve.NamedCurves.nistP256);
            ecdsa.ImportSubjectPublicKeyInfo(publicKeySpkiDer, out _);
        }
        catch (CryptographicException ex)
        {
            return VerificationResult.Fail(VerificationOutcome.InvalidPublicKey, ex.Message);
        }
        catch (Exception ex) when (ex is ArgumentException or NotSupportedException)
        {
            // ArgumentException can be thrown for zero-length or null-like inputs
            // before the CryptographicException layer.
            return VerificationResult.Fail(VerificationOutcome.InvalidPublicKey, ex.Message);
        }

        using (ecdsa)
        {
            // ── 2. Compute SHA-256 digest of the canonical challenge encoding ─
            // (Requirement 3.6: SHA-256 is the digest algorithm)
            byte[] digest = SHA256.HashData(challengeCanonical);

            // ── 3. Verify DER-encoded ECDSA signature (Requirement 3.2) ─────
            try
            {
                bool valid = ecdsa.VerifyHash(
                    digest,
                    signatureDer,
                    DSASignatureFormat.Rfc3279DerSequence);

                return valid
                    ? VerificationResult.Success()
                    : VerificationResult.Fail(VerificationOutcome.BadSignature);
            }
            catch (CryptographicException ex)
            {
                // Thrown when the signature bytes are not a valid DER structure.
                return VerificationResult.Fail(VerificationOutcome.InvalidSignatureFormat, ex.Message);
            }
        }
    }
}
