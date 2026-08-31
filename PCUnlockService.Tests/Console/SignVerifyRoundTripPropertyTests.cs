// Feature: pc-unlock, Property 24
// SignVerifyRoundTripPropertyTests — property-based tests for the Dev Console
// keygen → sign → verify round trip.
//
// Property 24: Development Console sign/verify round trip
//   Validates: Requirements 12.1
//   For any key pair from keygen and any challenge bytes, a Response produced
//   by sign is successfully verified by verify.
//
// These tests exercise the same System.Security.Cryptography code paths used
// by pcunlock keygen, pcunlock sign, and pcunlock verify — without spawning
// processes or touching the file system.

using System.Security.Cryptography;
using FsCheck;
using FsCheck.Fluent;
using FsCheck.Xunit;
using Xunit;

namespace PCUnlockService.Tests.Console;

/// <summary>
/// Property 24: For any key pair and any challenge bytes, a signature produced
/// by the sign logic is successfully verified by the verify logic.
/// Validates: Requirements 12.1
/// </summary>
public sealed class SignVerifyRoundTripPropertyTests
{
    // -----------------------------------------------------------------------
    // Core helpers — mirrors the exact code inside pcunlock sign and verify
    // -----------------------------------------------------------------------

    /// <summary>
    /// Mimics <c>pcunlock sign</c>: load a PEM private key, compute
    /// SHA-256(challengeBytes), sign with ECDSA-P256 DER encoding.
    /// </summary>
    private static byte[] Sign(string pemPrivateKey, byte[] challengeBytes)
    {
        using var ecdsa = ECDsa.Create();
        ecdsa.ImportFromPem(pemPrivateKey);
        byte[] digest = SHA256.HashData(challengeBytes);
        return ecdsa.SignHash(digest, DSASignatureFormat.Rfc3279DerSequence);
    }

    /// <summary>
    /// Mimics <c>pcunlock verify</c>: import the uncompressed public point,
    /// verify SHA-256(challengeBytes) against the DER signature.
    /// </summary>
    private static bool Verify(byte[] uncompressedPoint, byte[] challengeBytes, byte[] signatureDer)
    {
        if (uncompressedPoint.Length != 65 || uncompressedPoint[0] != 0x04)
            return false;

        try
        {
            var ecParams = new ECParameters
            {
                Curve = ECCurve.NamedCurves.nistP256,
                Q = new ECPoint
                {
                    X = uncompressedPoint[1..33],
                    Y = uncompressedPoint[33..65],
                }
            };
            using var ecdsa = ECDsa.Create(ecParams);
            byte[] digest = SHA256.HashData(challengeBytes);
            return ecdsa.VerifyHash(digest, signatureDer, DSASignatureFormat.Rfc3279DerSequence);
        }
        catch (CryptographicException)
        {
            return false;
        }
    }

    /// <summary>
    /// Mimics <c>pcunlock keygen</c>: generates a key pair, returns the PEM
    /// private key and the 65-byte uncompressed public point (04||X||Y).
    /// </summary>
    private static (string pemPrivateKey, byte[] uncompressedPoint) Keygen()
    {
        using var ecdsa = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        string pem = ecdsa.ExportPkcs8PrivateKeyPem();

        ECParameters ecParams = ecdsa.ExportParameters(includePrivateParameters: false);
        byte[] x = ecParams.Q.X!;
        byte[] y = ecParams.Q.Y!;

        // Pad coordinates to exactly 32 bytes (P-256 coordinates are always ≤32).
        static byte[] Pad32(byte[] b)
        {
            if (b.Length == 32) return b;
            var padded = new byte[32];
            b.CopyTo(padded, 32 - b.Length);
            return padded;
        }

        var point = new byte[65];
        point[0] = 0x04;
        Pad32(x).CopyTo(point, 1);
        Pad32(y).CopyTo(point, 33);

        return (pem, point);
    }

    // -----------------------------------------------------------------------
    // Property 24a — any 57-byte canonical challenge → sign+verify succeeds
    // -----------------------------------------------------------------------

    /// <summary>
    /// For any 57-byte canonical challenge payload, signing with a fresh key
    /// pair and verifying with the corresponding public key MUST succeed.
    /// Validates: Requirements 12.1
    /// </summary>
    [Property(MaxTest = 100)]
    public Property AnyCanonical57ByteChallenge_SignVerifyRoundTrip()
    {
        // Feature: pc-unlock, Property 24
        return Prop.ForAll(
            Arb.Generate<byte>().ArrayOf(57).ToArbitrary(),
            challenge =>
            {
                var (pem, pubPoint) = Keygen();
                byte[] sig = Sign(pem, challenge);
                bool valid = Verify(pubPoint, challenge, sig);

                return valid.Label($"sign→verify must succeed for any 57-byte challenge");
            });
    }

    // -----------------------------------------------------------------------
    // Property 24b — any challenge (1–256 bytes) → sign+verify succeeds
    // -----------------------------------------------------------------------

    /// <summary>
    /// For any non-empty challenge of arbitrary length (1–256 bytes),
    /// the round trip succeeds.
    /// Validates: Requirements 12.1
    /// </summary>
    [Property(MaxTest = 100)]
    public Property AnyNonEmptyChallenge_SignVerifyRoundTrip()
    {
        // Feature: pc-unlock, Property 24
        var gen = from len in Gen.Choose(1, 256)
                  from bytes in Gen.ArrayOf(len, Arb.Generate<byte>())
                  select bytes;

        return Prop.ForAll(
            gen.ToArbitrary(),
            challenge =>
            {
                var (pem, pubPoint) = Keygen();
                byte[] sig = Sign(pem, challenge);
                bool valid = Verify(pubPoint, challenge, sig);
                return valid.Label($"sign→verify must succeed for {challenge.Length}-byte challenge");
            });
    }

    // -----------------------------------------------------------------------
    // Fact: known 57-byte canonical challenge
    // -----------------------------------------------------------------------

    [Fact]
    public void KnownCanonicalChallenge_SignVerifyRoundTrip()
    {
        // Feature: pc-unlock, Property 24
        // Build a deterministic 57-byte challenge.
        var challenge = new byte[57];
        challenge[0] = 1; // version
        for (int i = 17; i < 49; i++) challenge[i] = (byte)(i % 256); // nonce
        BitConverter.GetBytes(DateTimeOffset.UtcNow.ToUnixTimeSeconds() + 60)
                    .CopyTo(challenge, 49);

        var (pem, pubPoint) = Keygen();
        byte[] sig = Sign(pem, challenge);
        bool valid = Verify(pubPoint, challenge, sig);

        Assert.True(valid, "sign→verify must succeed for a known canonical challenge");
    }

    // -----------------------------------------------------------------------
    // Fact: wrong public key → verify returns false
    // -----------------------------------------------------------------------

    [Fact]
    public void WrongPublicKey_VerifyReturnsFalse()
    {
        // Feature: pc-unlock, Property 24
        var challenge = new byte[57];
        RandomNumberGenerator.Fill(challenge);

        var (pem, _) = Keygen();
        byte[] sig = Sign(pem, challenge);

        // Different key pair — public key won't match the signature.
        var (_, wrongPubPoint) = Keygen();
        bool valid = Verify(wrongPubPoint, challenge, sig);

        Assert.False(valid, "verify must return false for a mismatched public key");
    }

    // -----------------------------------------------------------------------
    // Fact: tampered signature → verify returns false
    // -----------------------------------------------------------------------

    [Fact]
    public void TamperedSignature_VerifyReturnsFalse()
    {
        // Feature: pc-unlock, Property 24
        var challenge = new byte[57];
        RandomNumberGenerator.Fill(challenge);

        var (pem, pubPoint) = Keygen();
        byte[] sig = Sign(pem, challenge);

        // Flip the last byte of the signature.
        byte[] tampered = (byte[])sig.Clone();
        tampered[^1] ^= 0xFF;

        bool valid = Verify(pubPoint, challenge, tampered);

        // A tampered signature must not verify (may be BadSignature or InvalidFormat).
        Assert.False(valid, "verify must return false for a tampered signature");
    }
}
