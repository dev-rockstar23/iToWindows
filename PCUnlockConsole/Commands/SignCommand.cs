// Feature: pc-unlock — Development Console
// pcunlock sign --challenge <hex> --key <keyfile>
// Loads a PEM private key, signs the challenge bytes with ECDSA-P256-SHA256,
// prints the DER-encoded signature as hex to stdout.
// Requirements: 12.1, 12.4

using System.Security.Cryptography;

namespace PCUnlockConsole.Commands;

/// <summary>
/// Implements <c>pcunlock sign --challenge &lt;hex&gt; --key &lt;keyfile&gt;</c>.
/// <para>
/// Reads the private key from a PEM file (written by <c>pcunlock keygen</c>),
/// computes <c>SHA256(challengeBytes)</c>, signs with ECDSA-P256, and prints the
/// DER-encoded signature as an uppercase hex string.
/// </para>
/// </summary>
public static class SignCommand
{
    /// <summary>
    /// Entry point for the <c>sign</c> subcommand.
    /// </summary>
    /// <param name="args">Args after "sign".</param>
    /// <returns>Exit code: 0 on success, 1 on failure.</returns>
    public static int Run(string[] args)
    {
        string? challengeHex = null;
        string? keyFile = null;

        for (int i = 0; i < args.Length - 1; i++)
        {
            if (args[i] == "--challenge") challengeHex = args[i + 1];
            else if (args[i] == "--key") keyFile = args[i + 1];
        }

        if (challengeHex is null || keyFile is null)
        {
            Console.Error.WriteLine("Usage: pcunlock sign --challenge <hex> --key <keyfile>");
            return 1;
        }

        try
        {
            // Decode hex challenge
            byte[] challengeBytes;
            try
            {
                challengeBytes = Convert.FromHexString(challengeHex);
            }
            catch (FormatException)
            {
                Console.Error.WriteLine("sign error: --challenge must be a valid hex string");
                return 1;
            }

            // Load private key from PEM file
            if (!File.Exists(keyFile))
            {
                Console.Error.WriteLine($"sign error: key file not found: {keyFile}");
                return 1;
            }

            string pem = File.ReadAllText(keyFile);

            using var ecdsa = ECDsa.Create();
            ecdsa.ImportFromPem(pem);

            // Compute SHA-256 digest of the challenge bytes (Requirement 3.6)
            byte[] digest = SHA256.HashData(challengeBytes);

            // Sign with DER-encoded ECDSA signature (RFC 3279 SEQUENCE of r, s)
            byte[] signatureDer = ecdsa.SignHash(digest, DSASignatureFormat.Rfc3279DerSequence);

            // Print DER signature as hex to stdout
            Console.WriteLine(Convert.ToHexString(signatureDer));
            return 0;
        }
        catch (CryptographicException ex)
        {
            Console.Error.WriteLine($"sign error: {ex.Message}");
            return 1;
        }
        catch (Exception ex)
        {
            Console.Error.WriteLine($"sign error: {ex.Message}");
            return 1;
        }
    }
}
