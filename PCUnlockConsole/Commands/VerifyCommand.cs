// Feature: pc-unlock — Development Console
// pcunlock verify --challenge <hex> --sig <hex> --pubkey <hex>
// Imports the public key (uncompressed point 04||X||Y), verifies the DER signature;
// exits 0 on success, 1 on failure.
// Requirements: 12.1, 12.4

using System.Security.Cryptography;

namespace PCUnlockConsole.Commands;

/// <summary>
/// Implements <c>pcunlock verify --challenge &lt;hex&gt; --sig &lt;hex&gt; --pubkey &lt;hex&gt;</c>.
/// <para>
/// The public key is provided as the hex-encoded uncompressed P-256 point (04 || X || Y,
/// 65 bytes). The signature is a DER-encoded ECDSA-P256-SHA256 signature. The challenge
/// is the raw bytes that were signed (i.e. the canonical challenge encoding).
/// </para>
/// <para>
/// Exit code: 0 if signature is valid, 1 if invalid or on any error.
/// </para>
/// </summary>
public static class VerifyCommand
{
    /// <summary>
    /// Entry point for the <c>verify</c> subcommand.
    /// </summary>
    /// <param name="args">Args after "verify".</param>
    /// <returns>Exit code: 0 on valid signature, 1 on invalid or error.</returns>
    public static int Run(string[] args)
    {
        string? challengeHex = null;
        string? sigHex = null;
        string? pubkeyHex = null;

        for (int i = 0; i < args.Length - 1; i++)
        {
            if (args[i] == "--challenge") challengeHex = args[i + 1];
            else if (args[i] == "--sig") sigHex = args[i + 1];
            else if (args[i] == "--pubkey") pubkeyHex = args[i + 1];
        }

        if (challengeHex is null || sigHex is null || pubkeyHex is null)
        {
            Console.Error.WriteLine("Usage: pcunlock verify --challenge <hex> --sig <hex> --pubkey <hex>");
            return 1;
        }

        try
        {
            // Decode hex inputs
            byte[] challengeBytes;
            byte[] sigBytes;
            byte[] pubkeyBytes;

            try
            {
                challengeBytes = Convert.FromHexString(challengeHex);
                sigBytes = Convert.FromHexString(sigHex);
                pubkeyBytes = Convert.FromHexString(pubkeyHex);
            }
            catch (FormatException ex)
            {
                Console.Error.WriteLine($"verify error: invalid hex input — {ex.Message}");
                return 1;
            }

            // Import public key from uncompressed point (04 || X || Y, 65 bytes)
            // Use ECParameters directly to avoid needing full SPKI wrapping.
            if (pubkeyBytes.Length != 65 || pubkeyBytes[0] != 0x04)
            {
                Console.Error.WriteLine("verify error: --pubkey must be a 65-byte uncompressed P-256 point (04||X||Y)");
                return 1;
            }

            var ecParams = new ECParameters
            {
                Curve = ECCurve.NamedCurves.nistP256,
                Q = new ECPoint
                {
                    X = pubkeyBytes[1..33],
                    Y = pubkeyBytes[33..65]
                }
            };

            using var ecdsa = ECDsa.Create(ecParams);

            // Compute SHA-256 digest of the challenge bytes (Requirement 3.6)
            byte[] digest = SHA256.HashData(challengeBytes);

            // Verify DER-encoded ECDSA signature (RFC 3279 SEQUENCE of r, s)
            bool valid = ecdsa.VerifyHash(digest, sigBytes, DSASignatureFormat.Rfc3279DerSequence);

            // Exit 0 on valid, 1 on invalid — no message on failure per spec
            return valid ? 0 : 1;
        }
        catch (CryptographicException)
        {
            // Invalid key or malformed signature bytes — treat as verification failure
            return 1;
        }
        catch (Exception ex)
        {
            Console.Error.WriteLine($"verify error: {ex.Message}");
            return 1;
        }
    }
}
