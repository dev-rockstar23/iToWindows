// Feature: pc-unlock
// ICNGCryptoVerifier — abstracts the CNG-backed ECDSA-P256 verification step.
// Requirements: 3.2, 3.3, 3.6, 5.6
namespace PCUnlockService.Crypto;

/// <summary>
/// Verifies an ECDSA-P256 signature produced by the iPhone's Secure Enclave.
/// </summary>
/// <remarks>
/// All cryptographic operations are delegated to platform APIs
/// (<c>System.Security.Cryptography.ECDsa</c>, which wraps CNG on Windows).
/// No custom cryptographic primitives are used (Requirement 3.3).
/// </remarks>
public interface ICNGCryptoVerifier
{
    /// <summary>
    /// Verifies that <paramref name="signatureDer"/> is a valid ECDSA-P256 signature
    /// over <c>SHA-256(<paramref name="challengeCanonical57Bytes"/>)</c> using the
    /// public key encoded in <paramref name="publicKeySpkiDer"/>.
    /// </summary>
    /// <param name="publicKeySpkiDer">
    /// SubjectPublicKeyInfo DER encoding of the signer's P-256 public key (~91 bytes).
    /// </param>
    /// <param name="challengeCanonical57Bytes">
    /// The 57-byte canonical encoding of the challenge
    /// (<c>[version:1][sessionId:16][nonce:32][expiresAt:8]</c>).
    /// SHA-256 of this value is the digest that was signed.
    /// </param>
    /// <param name="signatureDer">
    /// DER-encoded ECDSA-P256 signature (typically 70–72 bytes).
    /// </param>
    /// <returns>
    /// A <see cref="VerificationResult"/> whose <see cref="VerificationResult.Outcome"/> is:
    /// <list type="bullet">
    ///   <item><see cref="VerificationOutcome.Success"/> — signature is valid.</item>
    ///   <item><see cref="VerificationOutcome.BadSignature"/> — signature is structurally sound but does not verify.</item>
    ///   <item><see cref="VerificationOutcome.InvalidPublicKey"/> — public key bytes could not be imported.</item>
    ///   <item><see cref="VerificationOutcome.InvalidSignatureFormat"/> — signature bytes are not valid DER.</item>
    /// </list>
    /// </returns>
    VerificationResult Verify(
        byte[] publicKeySpkiDer,
        byte[] challengeCanonical57Bytes,
        byte[] signatureDer);
}
