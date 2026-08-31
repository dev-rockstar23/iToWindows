// Feature: pc-unlock
// Unit tests for CNGCryptoVerifier.
// Requirements: 3.2, 3.3, 3.6, 5.6
//
// These tests use software ECDsa keys (not Secure Enclave — runs on any Windows machine).
// All cryptographic operations use System.Security.Cryptography (CNG on Windows),
// matching the production code path exactly.

using System.Security.Cryptography;
using PCUnlockService.Crypto;
using Xunit;

namespace PCUnlockService.Tests.Crypto;

/// <summary>
/// Unit tests for <see cref="CNGCryptoVerifier"/>.
/// Uses software-backed P-256 keys so the tests can run without a Secure Enclave.
/// Validates: Requirements 3.2, 3.3, 3.6, 5.6
/// </summary>
public sealed class CNGCryptoVerifierTests
{
    // -------------------------------------------------------------------------
    // Helpers
    // -------------------------------------------------------------------------

    /// <summary>
    /// Creates a 57-byte canonical challenge payload.
    /// Layout: [version:1][sessionId:16 LE][nonce:32][expiresAt:8 LE]
    /// </summary>
    private static byte[] MakeCanonicalChallenge()
    {
        var buf = new byte[57];
        buf[0] = 1; // version
        Guid.NewGuid().ToByteArray().CopyTo(buf, 1);            // sessionId (16 bytes)
        RandomNumberGenerator.GetBytes(32).CopyTo(buf, 17);     // nonce (32 bytes)
        BitConverter.GetBytes(DateTimeOffset.UtcNow.ToUnixTimeSeconds() + 60)
                    .CopyTo(buf, 49);                            // expiresAt (8 bytes LE)
        return buf;
    }

    /// <summary>
    /// Generates a software P-256 key pair, signs the digest of the given
    /// challenge, and returns the SPKI DER public key + DER signature.
    /// </summary>
    private static (byte[] spkiDer, byte[] signatureDer) SignChallenge(byte[] challengeCanonical)
    {
        using var ecdsa = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        byte[] spkiDer = ecdsa.ExportSubjectPublicKeyInfo();
        byte[] digest = SHA256.HashData(challengeCanonical);
        byte[] signatureDer = ecdsa.SignHash(digest, DSASignatureFormat.Rfc3279DerSequence);
        return (spkiDer, signatureDer);
    }

    // -------------------------------------------------------------------------
    // Tests
    // -------------------------------------------------------------------------

    /// <summary>
    /// A correctly signed challenge MUST verify as <see cref="VerificationOutcome.Success"/>.
    /// Validates: Requirements 3.2, 3.6
    /// </summary>
    [Fact]
    public void Verify_ValidSignature_ReturnsSuccess()
    {
        // Arrange
        byte[] challenge = MakeCanonicalChallenge();
        var (spkiDer, signatureDer) = SignChallenge(challenge);
        var verifier = new CNGCryptoVerifier();

        // Act
        VerificationResult result = verifier.Verify(spkiDer, challenge, signatureDer);

        // Assert
        Assert.Equal(VerificationOutcome.Success, result.Outcome);
        Assert.Null(result.ErrorMessage);
    }

    /// <summary>
    /// A signature with a single tampered byte MUST be rejected as
    /// <see cref="VerificationOutcome.BadSignature"/> (or
    /// <see cref="VerificationOutcome.InvalidSignatureFormat"/> if the tamper
    /// corrupts the DER structure).
    /// Validates: Requirements 3.2, 5.6
    /// </summary>
    [Fact]
    public void Verify_WrongSignature_ReturnsBadSignature()
    {
        // Arrange
        byte[] challenge = MakeCanonicalChallenge();
        var (spkiDer, signatureDer) = SignChallenge(challenge);

        // Tamper with the last byte of the signature — this keeps the DER wrapper
        // intact (header + length bytes at the start are untouched) while corrupting
        // the r or s integer value, so the verifier sees a structurally valid but
        // mathematically invalid signature.
        byte[] tamperedSig = (byte[])signatureDer.Clone();
        tamperedSig[^1] ^= 0xFF;

        var verifier = new CNGCryptoVerifier();

        // Act
        VerificationResult result = verifier.Verify(spkiDer, challenge, tamperedSig);

        // Assert — tampered sig is either BadSignature or InvalidSignatureFormat
        // (flipping the last byte may or may not break DER encoding depending on
        //  the exact integer values in r/s, so we accept both rejection outcomes).
        Assert.True(
            result.Outcome is VerificationOutcome.BadSignature
                           or VerificationOutcome.InvalidSignatureFormat,
            $"Expected BadSignature or InvalidSignatureFormat, got {result.Outcome}");
    }

    /// <summary>
    /// Garbage bytes for the public key MUST be rejected as
    /// <see cref="VerificationOutcome.InvalidPublicKey"/>.
    /// Validates: Requirements 3.2, 3.3
    /// </summary>
    [Fact]
    public void Verify_InvalidPublicKey_ReturnsInvalidPublicKey()
    {
        // Arrange
        byte[] challenge = MakeCanonicalChallenge();
        byte[] badKey = new byte[] { 0xDE, 0xAD, 0xBE, 0xEF };

        // Use a valid signature shape so the test is isolated to the key import step.
        var (_, signatureDer) = SignChallenge(challenge);

        var verifier = new CNGCryptoVerifier();

        // Act
        VerificationResult result = verifier.Verify(badKey, challenge, signatureDer);

        // Assert
        Assert.Equal(VerificationOutcome.InvalidPublicKey, result.Outcome);
        Assert.NotNull(result.ErrorMessage);
    }

    /// <summary>
    /// A signature produced over challenge1 MUST NOT verify against challenge2,
    /// and MUST be rejected as <see cref="VerificationOutcome.BadSignature"/>.
    /// Validates: Requirements 3.2, 3.6, 5.6
    /// </summary>
    [Fact]
    public void Verify_ModifiedChallenge_ReturnsBadSignature()
    {
        // Arrange — sign challenge1, then try to verify against challenge2
        byte[] challenge1 = MakeCanonicalChallenge();
        byte[] challenge2 = MakeCanonicalChallenge();

        // Ensure challenge2 actually differs from challenge1 (nonce is random,
        // so collision probability is astronomically small, but we guard anyway).
        // Mutate the nonce bytes in challenge2 to be definitely different.
        challenge2[17] ^= 0xFF;

        var (spkiDer, signatureDer) = SignChallenge(challenge1);
        var verifier = new CNGCryptoVerifier();

        // Act — verify the challenge1 signature against challenge2's digest
        VerificationResult result = verifier.Verify(spkiDer, challenge2, signatureDer);

        // Assert
        Assert.Equal(VerificationOutcome.BadSignature, result.Outcome);
    }
}
