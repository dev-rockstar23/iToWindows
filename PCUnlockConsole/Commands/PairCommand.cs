// Feature: pc-unlock
// pcunlock pair --role pc|iphone
// Requirements: 12.3, 12.5

using System.Security.Cryptography;
using System.Text.Json;
using System.Text.Json.Serialization;

namespace PCUnlockConsole.Commands;

/// <summary>
/// Implements <c>pcunlock pair --role pc|iphone</c>.
/// Runs one side of the pairing flow using a test registry (not the production
/// Credential Provider).
/// </summary>
public static class PairCommand
{
    // PCUnlock BLE service UUID (for the QR payload svc field).
    private static readonly Guid BleServiceUuid = new("A1B2C3D4-E5F6-7890-ABCD-EF1234567890");

    public static async Task<int> RunAsync(string[] args)
    {
        string? role = null;
        for (int i = 0; i < args.Length - 1; i++)
        {
            if (args[i] == "--role") role = args[i + 1].ToLowerInvariant();
        }

        if (role is null)
        {
            Console.Error.WriteLine("Usage: pcunlock pair --role pc|iphone");
            return 1;
        }

        return role switch
        {
            "pc"     => await RunPcSideAsync(),
            "iphone" => await RunIphoneSideAsync(),
            _        => PrintError($"Unknown role '{role}'. Use 'pc' or 'iphone'.")
        };
    }

    // -------------------------------------------------------------------------
    // PC side
    // -------------------------------------------------------------------------

    private static async Task<int> RunPcSideAsync()
    {
        Console.WriteLine("pair [PC]: generating pairing payload...");

        // Generate 16-byte pcIdentityToken.
        byte[] pcIdentityToken = RandomNumberGenerator.GetBytes(16);

        // Generate 6-char alphanumeric Pairing_Code.
        string pairingCode = GeneratePairingCode();

        // Build PairingPayload JSON.
        var payload = new PairingPayloadJson
        {
            V    = 1,
            PcId = Base64UrlEncode(pcIdentityToken),
            Code = pairingCode,
            Svc  = Base64UrlEncode(BleServiceUuid.ToByteArray()),
        };

        string payloadJson = JsonSerializer.Serialize(payload);

        Console.WriteLine();
        Console.WriteLine($"  Pairing Code : {pairingCode}");
        Console.WriteLine($"  Payload JSON : {payloadJson}");
        Console.WriteLine();
        Console.WriteLine("  QR Code (text representation — render with a QR library in production):");
        Console.WriteLine($"  {payloadJson}");
        Console.WriteLine();
        Console.WriteLine("pair [PC]: waiting for iPhone to send PairingRequest (paste below and press Enter):");
        Console.WriteLine("  Format: <hex-encoded-public-key> <pairing-code-echo>");
        Console.WriteLine();

        string? input = Console.ReadLine();
        if (string.IsNullOrWhiteSpace(input))
        {
            Console.Error.WriteLine("pair [PC]: no input received.");
            return 1;
        }

        // Parse: <pubkeyHex> <codeEcho>
        string[] parts = input.Trim().Split(' ', 2);
        if (parts.Length < 2)
        {
            Console.Error.WriteLine("pair [PC]: invalid input format. Expected: <pubkeyHex> <codeEcho>");
            return 1;
        }

        string pubkeyHex = parts[0];
        string codeEcho  = parts[1];

        // Verify code echo.
        if (!string.Equals(codeEcho, pairingCode, StringComparison.OrdinalIgnoreCase))
        {
            Console.Error.WriteLine($"pair [PC]: Pairing_Code mismatch! Expected '{pairingCode}', got '{codeEcho}'.");
            return 1;
        }

        byte[] publicKeyDER;
        try
        {
            publicKeyDER = Convert.FromHexString(pubkeyHex);
        }
        catch (FormatException)
        {
            Console.Error.WriteLine("pair [PC]: invalid public key hex.");
            return 1;
        }

        // Write DeviceRecord to test registry file.
        var testRegistryPath = Path.Combine(
            Path.GetTempPath(), "pcunlock_test_registry.json");

        var deviceRecord = new DeviceRecordJson
        {
            DeviceId        = Guid.NewGuid().ToString(),
            DeviceName      = "Test iPhone (Dev Console)",
            PublicKeyDER    = pubkeyHex,
            PairedAt        = DateTimeOffset.UtcNow.ToString("o"),
            PcIdentityToken = Convert.ToHexString(pcIdentityToken),
        };

        // Append to test registry.
        var records = new List<DeviceRecordJson>();
        if (File.Exists(testRegistryPath))
        {
            try
            {
                var existing = JsonSerializer.Deserialize<List<DeviceRecordJson>>(
                    File.ReadAllText(testRegistryPath));
                if (existing is not null) records.AddRange(existing);
            }
            catch { /* start fresh if corrupt */ }
        }
        records.Add(deviceRecord);
        File.WriteAllText(testRegistryPath,
            JsonSerializer.Serialize(records, new JsonSerializerOptions { WriteIndented = true }));

        Console.WriteLine();
        Console.WriteLine($"pair [PC]: pairing complete!");
        Console.WriteLine($"  DeviceId    : {deviceRecord.DeviceId}");
        Console.WriteLine($"  DeviceName  : {deviceRecord.DeviceName}");
        Console.WriteLine($"  Registry    : {testRegistryPath}");
        Console.WriteLine();
        Console.WriteLine("pair [PC]: send 'PAIRING_COMPLETE' to the iPhone console.");

        return 0;
    }

    // -------------------------------------------------------------------------
    // iPhone side
    // -------------------------------------------------------------------------

    private static async Task<int> RunIphoneSideAsync()
    {
        Console.WriteLine("pair [iPhone]: paste the QR payload JSON from the PC console, then press Enter:");

        string? payloadJson = Console.ReadLine();
        if (string.IsNullOrWhiteSpace(payloadJson))
        {
            Console.Error.WriteLine("pair [iPhone]: no payload received.");
            return 1;
        }

        PairingPayloadJson? payload;
        try
        {
            payload = JsonSerializer.Deserialize<PairingPayloadJson>(payloadJson);
        }
        catch (JsonException)
        {
            Console.Error.WriteLine("pair [iPhone]: invalid JSON payload.");
            return 1;
        }

        if (payload is null)
        {
            Console.Error.WriteLine("pair [iPhone]: null payload.");
            return 1;
        }

        Console.WriteLine();
        Console.WriteLine($"  Decoded Pairing_Code : {payload.Code}");
        Console.WriteLine($"  PC Identity (base64url): {payload.PcId}");
        Console.WriteLine();
        Console.WriteLine($"pair [iPhone]: display this code to the user: [{payload.Code}]");
        Console.WriteLine("pair [iPhone]: press Enter when the user has confirmed the code matches...");
        Console.ReadLine();

        // Generate a mock P-256 key pair (simulates iOS Secure Enclave).
        using var ecdsa = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        string pemPrivate = ecdsa.ExportPkcs8PrivateKeyPem();
        var ecParams = ecdsa.ExportParameters(false);

        byte[] x = ecParams.Q.X!;
        byte[] y = ecParams.Q.Y!;
        var pubPoint = new byte[65];
        pubPoint[0] = 0x04;
        PadTo32(x).CopyTo(pubPoint, 1);
        PadTo32(y).CopyTo(pubPoint, 33);

        string pubkeyHex = Convert.ToHexString(pubPoint);

        Console.WriteLine();
        Console.WriteLine($"pair [iPhone]: generated mock P-256 key pair.");
        Console.WriteLine($"  Public key (hex) : {pubkeyHex}");
        Console.WriteLine();
        Console.WriteLine("pair [iPhone]: sending PairingRequest to PC console.");
        Console.WriteLine("  Copy the line below and paste it into the PC console:");
        Console.WriteLine();
        Console.WriteLine($"  {pubkeyHex} {payload.Code}");
        Console.WriteLine();
        Console.WriteLine("pair [iPhone]: waiting for PairingComplete acknowledgement...");
        Console.WriteLine("  Press Enter when the PC console prints 'PAIRING_COMPLETE'.");
        Console.ReadLine();

        // Save key file for use with pcunlock sign.
        string keyFile = $"pcunlock_pair_{payload.Code}.key";
        File.WriteAllText(keyFile, pemPrivate);

        Console.WriteLine($"pair [iPhone]: pairing complete! Private key saved to: {keyFile}");
        return 0;
    }

    // -------------------------------------------------------------------------
    // Helpers
    // -------------------------------------------------------------------------

    private static string GeneratePairingCode()
    {
        const string Alphabet    = "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
        int maxUnbiased = (256 / Alphabet.Length) * Alphabet.Length;
        var code   = new char[6];
        var buffer = new byte[1];
        int filled = 0;
        while (filled < 6)
        {
            RandomNumberGenerator.Fill(buffer);
            if (buffer[0] < maxUnbiased)
                code[filled++] = Alphabet[buffer[0] % Alphabet.Length];
        }
        return new string(code);
    }

    private static string Base64UrlEncode(byte[] bytes) =>
        Convert.ToBase64String(bytes)
               .Replace('+', '-').Replace('/', '_').TrimEnd('=');

    private static byte[] PadTo32(byte[] b)
    {
        if (b.Length == 32) return b;
        var padded = new byte[32];
        b.CopyTo(padded, 32 - b.Length);
        return padded;
    }

    private static int PrintError(string msg)
    {
        Console.Error.WriteLine(msg);
        return 1;
    }

    // -------------------------------------------------------------------------
    // JSON models (local to this command — not the production DeviceRecord)
    // -------------------------------------------------------------------------

    private sealed class PairingPayloadJson
    {
        [JsonPropertyName("v")]    public int    V    { get; set; }
        [JsonPropertyName("pcId")] public string PcId { get; set; } = string.Empty;
        [JsonPropertyName("code")] public string Code { get; set; } = string.Empty;
        [JsonPropertyName("svc")]  public string Svc  { get; set; } = string.Empty;
    }

    private sealed class DeviceRecordJson
    {
        [JsonPropertyName("deviceId")]        public string DeviceId        { get; set; } = string.Empty;
        [JsonPropertyName("deviceName")]      public string DeviceName      { get; set; } = string.Empty;
        [JsonPropertyName("publicKeyDER")]    public string PublicKeyDER    { get; set; } = string.Empty;
        [JsonPropertyName("pairedAt")]        public string PairedAt        { get; set; } = string.Empty;
        [JsonPropertyName("pcIdentityToken")] public string PcIdentityToken { get; set; } = string.Empty;
    }
}
