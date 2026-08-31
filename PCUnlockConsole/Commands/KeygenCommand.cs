// Feature: pc-unlock — Development Console
// pcunlock keygen: generate ECC P-256 key pair using System.Security.Cryptography (CNG on Windows).
// Requirements: 12.1, 12.4

using System.Security.Cryptography;

namespace PCUnlockConsole.Commands;

/// <summary>
/// Implements <c>pcunlock keygen</c>.
/// <para>
/// Generates an ECC P-256 key pair, prints the public key as a hex-encoded uncompressed
/// point (04 || X || Y, 65 bytes) to stdout, and saves the private key as a PEM file.
/// </para>
/// </summary>
public static class KeygenCommand
{
    /// <summary>
    /// Entry point for the <c>keygen</c> subcommand.
    /// </summary>
    /// <param name="args">Remaining args after "keygen" (expected: none, or --out &lt;file&gt;).</param>
    /// <returns>Exit code: 0 on success, 1 on failure.</returns>
    public static int Run(string[] args)
    {
        // Parse optional --out <file> argument; default to "pcunlock.key"
        string keyFile = "pcunlock.key";
        for (int i = 0; i < args.Length - 1; i++)
        {
            if (args[i] == "--out")
            {
                keyFile = args[i + 1];
                break;
            }
        }

        try
        {
            using var ecdsa = ECDsa.Create(ECCurve.NamedCurves.nistP256);

            // Export private key as PEM (PKCS#8 EncryptedPrivateKeyInfo not needed here;
            // plain PKCS#8 PEM is sufficient for the dev console key file).
            string pemPrivate = ecdsa.ExportPkcs8PrivateKeyPem();
            File.WriteAllText(keyFile, pemPrivate);

            // Export public key as uncompressed point: 04 || X || Y (65 bytes)
            ECParameters ecParams = ecdsa.ExportParameters(includePrivateParameters: false);
            byte[] uncompressed = ExportUncompressedPoint(ecParams);
            Console.WriteLine(Convert.ToHexString(uncompressed));

            return 0;
        }
        catch (Exception ex)
        {
            Console.Error.WriteLine($"keygen error: {ex.Message}");
            return 1;
        }
    }

    /// <summary>
    /// Builds the 65-byte uncompressed point encoding: 04 || X (32 bytes) || Y (32 bytes).
    /// </summary>
    internal static byte[] ExportUncompressedPoint(ECParameters ecParams)
    {
        byte[] x = ecParams.Q.X ?? throw new CryptographicException("ECParameters.Q.X is null");
        byte[] y = ecParams.Q.Y ?? throw new CryptographicException("ECParameters.Q.Y is null");

        // P-256 coordinates are always 32 bytes; pad with leading zeros if shorter.
        static byte[] Pad32(byte[] coord)
        {
            if (coord.Length == 32) return coord;
            var padded = new byte[32];
            coord.CopyTo(padded, 32 - coord.Length);
            return padded;
        }

        var point = new byte[65];
        point[0] = 0x04;
        Pad32(x).CopyTo(point, 1);
        Pad32(y).CopyTo(point, 33);
        return point;
    }
}
