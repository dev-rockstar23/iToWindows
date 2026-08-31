// Feature: pc-unlock
// pcunlock ble-sim central — simulates the PC BLE central role.
// Requirements: 12.2

using System.Runtime.InteropServices.WindowsRuntime;
using Windows.Devices.Bluetooth;
using Windows.Devices.Bluetooth.Advertisement;
using Windows.Devices.Bluetooth.GenericAttributeProfile;
using Windows.Storage.Streams;

namespace PCUnlockConsole.Commands.BleSim;

/// <summary>
/// Implements <c>pcunlock ble-sim central</c>.
/// Scans for the PCUnlock GATT service, connects, writes a mock 57-byte
/// Challenge, awaits the Response Notify, and prints the response hex.
/// </summary>
public static class BleSimCentralCommand
{
    private static readonly Guid ServiceUuid       = new("A1B2C3D4-E5F6-7890-ABCD-EF1234567890");
    private static readonly Guid ChallengeCharUuid = new("A1B2C3D4-E5F6-7890-ABCD-EF1234567891");
    private static readonly Guid ResponseCharUuid  = new("A1B2C3D4-E5F6-7890-ABCD-EF1234567892");
    private static readonly TimeSpan ScanTimeout   = TimeSpan.FromSeconds(15);

    public static async Task<int> RunAsync(string[] args)
    {
        Console.WriteLine("ble-sim central: scanning for PCUnlock peripheral...");
        Console.WriteLine($"  Service UUID: {ServiceUuid}");
        Console.WriteLine($"  Timeout: {ScanTimeout.TotalSeconds}s");

        ulong? foundAddress = null;
        var foundSemaphore  = new SemaphoreSlim(0, 1);

        var watcher = new BluetoothLEAdvertisementWatcher();
        watcher.AdvertisementFilter.Advertisement.ServiceUuids.Add(ServiceUuid);
        watcher.ScanningMode = BluetoothLEScanningMode.Active;

        watcher.Received += (sender, e) =>
        {
            if (foundAddress.HasValue) return;
            foundAddress = e.BluetoothAddress;
            Console.WriteLine($"  [CENTRAL] Peripheral found at {e.BluetoothAddress:X12}");
            try { foundSemaphore.Release(); } catch { /* already released */ }
        };

        watcher.Start();

        bool found = await foundSemaphore.WaitAsync(ScanTimeout).ConfigureAwait(false);
        watcher.Stop();

        if (!found || !foundAddress.HasValue)
        {
            Console.Error.WriteLine("ble-sim central: no peripheral found within 15 seconds.");
            return 1;
        }

        try
        {
            using var device = await BluetoothLEDevice.FromBluetoothAddressAsync(foundAddress.Value);
            if (device is null)
            {
                Console.Error.WriteLine("ble-sim central: failed to connect to device.");
                return 1;
            }

            Console.WriteLine($"  [CENTRAL] Connected to {device.Name}.");

            var servicesResult = await device.GetGattServicesForUuidAsync(
                ServiceUuid, BluetoothCacheMode.Uncached);
            if (servicesResult.Status != GattCommunicationStatus.Success
                || servicesResult.Services.Count == 0)
            {
                Console.Error.WriteLine($"ble-sim central: GATT service not found ({servicesResult.Status}).");
                return 1;
            }

            using var service = servicesResult.Services[0];

            // ── Subscribe to Response characteristic ──────────────────────
            var responseResult = await service.GetCharacteristicsForUuidAsync(
                ResponseCharUuid, BluetoothCacheMode.Uncached);
            if (responseResult.Status != GattCommunicationStatus.Success
                || responseResult.Characteristics.Count == 0)
            {
                Console.Error.WriteLine("ble-sim central: Response characteristic not found.");
                return 1;
            }

            var responseChar = responseResult.Characteristics[0];
            var responseSemaphore = new SemaphoreSlim(0, 1);
            byte[]? responseBytes = null;

            responseChar.ValueChanged += (sender, e) =>
            {
                responseBytes = e.CharacteristicValue.ToArray();
                Console.WriteLine($"  [CENTRAL] Response received ({responseBytes.Length} bytes): {Convert.ToHexString(responseBytes)}");
                try { responseSemaphore.Release(); } catch { /* already released */ }
            };

            await responseChar.WriteClientCharacteristicConfigurationDescriptorAsync(
                GattClientCharacteristicConfigurationDescriptorValue.Notify);

            // ── Write mock Challenge ──────────────────────────────────────
            var challengeResult = await service.GetCharacteristicsForUuidAsync(
                ChallengeCharUuid, BluetoothCacheMode.Uncached);
            if (challengeResult.Status != GattCommunicationStatus.Success
                || challengeResult.Characteristics.Count == 0)
            {
                Console.Error.WriteLine("ble-sim central: Challenge characteristic not found.");
                return 1;
            }

            var challengeChar  = challengeResult.Characteristics[0];
            byte[] mockChallenge = BuildMockChallenge();

            Console.WriteLine($"  [CENTRAL] Writing mock Challenge: {Convert.ToHexString(mockChallenge)}");

            using var writer = new DataWriter();
            writer.WriteBytes(mockChallenge);
            var writeStatus = await challengeChar.WriteValueWithResultAsync(
                writer.DetachBuffer(), GattWriteOption.WriteWithResponse);

            if (writeStatus.Status != GattCommunicationStatus.Success)
            {
                Console.Error.WriteLine($"ble-sim central: Challenge write failed ({writeStatus.Status}).");
                return 1;
            }

            // ── Wait for Response notification ────────────────────────────
            bool notified = await responseSemaphore.WaitAsync(ScanTimeout).ConfigureAwait(false);
            if (!notified || responseBytes is null)
            {
                Console.Error.WriteLine("ble-sim central: timed out waiting for Response.");
                return 1;
            }

            Console.WriteLine($"ble-sim central: Response hex = {Convert.ToHexString(responseBytes)}");
            return 0;
        }
        catch (Exception ex)
        {
            Console.Error.WriteLine($"ble-sim central error: {ex.Message}");
            return 1;
        }
    }

    /// <summary>Builds a deterministic 57-byte mock Challenge payload.</summary>
    private static byte[] BuildMockChallenge()
    {
        var buf = new byte[57];
        buf[0] = 1; // version = 1
        // sessionId bytes 1-16: sequential
        for (int i = 1; i <= 16; i++) buf[i] = (byte)i;
        // nonce bytes 17-48: 0xAB
        for (int i = 17; i <= 48; i++) buf[i] = 0xAB;
        // expiresAt bytes 49-56: now + 60s LE int64
        long expiresAt = DateTimeOffset.UtcNow.ToUnixTimeSeconds() + 60;
        BitConverter.GetBytes(expiresAt).CopyTo(buf, 49);
        return buf;
    }
}
