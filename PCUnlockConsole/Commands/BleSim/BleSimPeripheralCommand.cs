// Feature: pc-unlock
// pcunlock ble-sim peripheral — simulates the iPhone BLE peripheral role.
// Requirements: 12.2

using System.Runtime.InteropServices.WindowsRuntime;
using Windows.Devices.Bluetooth.GenericAttributeProfile;
using Windows.Storage.Streams;

namespace PCUnlockConsole.Commands.BleSim;

/// <summary>
/// Implements <c>pcunlock ble-sim peripheral</c>.
/// Advertises the PCUnlock GATT service, accepts a Challenge write on the
/// Challenge characteristic, and responds with a mock signed Response via
/// Notify on the Response characteristic.
/// </summary>
public static class BleSimPeripheralCommand
{
    // PCUnlock GATT UUIDs
    private static readonly Guid ServiceUuid          = new("A1B2C3D4-E5F6-7890-ABCD-EF1234567890");
    private static readonly Guid ChallengeCharUuid    = new("A1B2C3D4-E5F6-7890-ABCD-EF1234567891");
    private static readonly Guid ResponseCharUuid     = new("A1B2C3D4-E5F6-7890-ABCD-EF1234567892");

    public static async Task<int> RunAsync(string[] args)
    {
        Console.WriteLine("ble-sim peripheral: starting PCUnlock GATT peripheral...");
        Console.WriteLine($"  Service UUID:   {ServiceUuid}");
        Console.WriteLine($"  Challenge char: {ChallengeCharUuid}");
        Console.WriteLine($"  Response char:  {ResponseCharUuid}");

        GattServiceProvider? serviceProvider = null;

        try
        {
            // Create the GATT service provider.
            var result = await GattServiceProvider.CreateAsync(ServiceUuid);
            if (result.Error != BluetoothError.Success)
            {
                Console.Error.WriteLine($"ble-sim peripheral: failed to create GATT service: {result.Error}");
                return 1;
            }
            serviceProvider = result.ServiceProvider;

            // ── Challenge characteristic (Write) ──────────────────────────
            var challengeParams = new GattLocalCharacteristicParameters
            {
                CharacteristicProperties = GattCharacteristicProperties.Write,
                WriteProtectionLevel     = GattProtectionLevel.EncryptionAndAuthenticationRequired,
                UserDescription          = "Challenge",
            };
            var challengeResult = await serviceProvider.Service
                .CreateCharacteristicAsync(ChallengeCharUuid, challengeParams);
            if (challengeResult.Error != BluetoothError.Success)
            {
                Console.Error.WriteLine($"ble-sim peripheral: failed to create Challenge characteristic: {challengeResult.Error}");
                return 1;
            }
            var challengeChar = challengeResult.Characteristic;

            // ── Response characteristic (Notify) ─────────────────────────
            var responseParams = new GattLocalCharacteristicParameters
            {
                CharacteristicProperties = GattCharacteristicProperties.Notify,
                WriteProtectionLevel     = GattProtectionLevel.EncryptionAndAuthenticationRequired,
                UserDescription          = "Response",
            };
            var responseResult = await serviceProvider.Service
                .CreateCharacteristicAsync(ResponseCharUuid, responseParams);
            if (responseResult.Error != BluetoothError.Success)
            {
                Console.Error.WriteLine($"ble-sim peripheral: failed to create Response characteristic: {responseResult.Error}");
                return 1;
            }
            var responseChar = responseResult.Characteristic;

            // ── Wire up Challenge write handler ───────────────────────────
            challengeChar.WriteRequested += async (sender, args2) =>
            {
                using var deferral = args2.GetDeferral();
                var request = await args2.GetRequestAsync();

                byte[] challengeBytes = request.Value.ToArray();
                Console.WriteLine($"  [PERIPHERAL] Received Challenge ({challengeBytes.Length} bytes): {Convert.ToHexString(challengeBytes)}");

                // Complete the write request.
                request.Respond();

                // Build a mock Response: 1-byte version + 16-byte sessionId
                // (from challenge bytes 1-16) + 16-byte deviceId + 32-byte stub sig.
                byte[] mockResponse = BuildMockResponse(challengeBytes);
                Console.WriteLine($"  [PERIPHERAL] Sending mock Response ({mockResponse.Length} bytes): {Convert.ToHexString(mockResponse)}");

                // Notify all subscribed centrals.
                using var writer = new DataWriter();
                writer.WriteBytes(mockResponse);
                var notifyResult = await responseChar.NotifyValueAsync(writer.DetachBuffer());
                Console.WriteLine($"  [PERIPHERAL] Notify result: {notifyResult.Count} subscriber(s) reached.");
            };

            // ── Start advertising ─────────────────────────────────────────
            var advertisingParams = new GattServiceProviderAdvertisingParameters
            {
                IsConnectable  = true,
                IsDiscoverable = true,
            };
            serviceProvider.StartAdvertising(advertisingParams);

            Console.WriteLine("ble-sim peripheral: advertising. Press Enter to stop.");
            Console.ReadLine();

            serviceProvider.StopAdvertising();
            Console.WriteLine("ble-sim peripheral: stopped.");
            return 0;
        }
        catch (Exception ex)
        {
            Console.Error.WriteLine($"ble-sim peripheral error: {ex.Message}");
            return 1;
        }
        finally
        {
            serviceProvider?.StopAdvertising();
        }
    }

    /// <summary>
    /// Builds a mock 65-byte Response:
    /// [version:1][sessionId:16 from challenge][deviceId:16 zeros][sig:32 zeros].
    /// </summary>
    private static byte[] BuildMockResponse(byte[] challengeBytes)
    {
        var response = new byte[65];
        response[0] = 1; // version

        // Copy sessionId from challenge bytes 1–16 (if available).
        if (challengeBytes.Length >= 17)
            Array.Copy(challengeBytes, 1, response, 1, 16);

        // deviceId and signature are zeroed (mock).
        return response;
    }
}
