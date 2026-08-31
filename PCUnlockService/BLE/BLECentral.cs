// Feature: pc-unlock
// BLECentral — Windows BLE Central implementation using Windows.Devices.Bluetooth
// WinRT APIs.
// Requirements: 4.1, 4.3, 4.6

using Microsoft.Extensions.Logging;
using System.Runtime.InteropServices.WindowsRuntime;
using Windows.Devices.Bluetooth;
using Windows.Devices.Bluetooth.Advertisement;
using Windows.Devices.Bluetooth.GenericAttributeProfile;
using Windows.Storage.Streams;

namespace PCUnlockService.BLE;

/// <summary>
/// Windows BLE Central that scans for peripherals advertising the PCUnlock
/// GATT service UUID, connects, performs the Challenge/Response exchange, and
/// returns a typed <see cref="BLESessionResult"/>.
/// </summary>
/// <remarks>
/// Thread-safety: <see cref="RunSessionAsync"/> is not re-entrant.  The caller
/// (Session/Nonce Manager) must ensure only one session runs at a time.
/// </remarks>
public sealed class BLECentral : IBLECentral, IDisposable
{
    // -------------------------------------------------------------------------
    // BLE UUIDs (Requirement: design spec §BLE GATT Service Design)
    // -------------------------------------------------------------------------

    /// <summary>PCUnlock GATT Service UUID.</summary>
    public static readonly Guid ServiceUuid =
        new("A1B2C3D4-E5F6-7890-ABCD-EF1234567890");

    /// <summary>Challenge characteristic UUID — Write with response (57 bytes).</summary>
    public static readonly Guid ChallengeCharacteristicUuid =
        new("A1B2C3D4-E5F6-7890-ABCD-EF1234567891");

    /// <summary>Response characteristic UUID — Notify.</summary>
    public static readonly Guid ResponseCharacteristicUuid =
        new("A1B2C3D4-E5F6-7890-ABCD-EF1234567892");

    /// <summary>Device Advertisement Data characteristic UUID — Read.</summary>
    public static readonly Guid DeviceAdvDataCharacteristicUuid =
        new("A1B2C3D4-E5F6-7890-ABCD-EF1234567894");

    // -------------------------------------------------------------------------
    // Constants
    // -------------------------------------------------------------------------

    /// <summary>Total BLE session timeout: 15 seconds (Requirement 4.6).</summary>
    public static readonly TimeSpan SessionTimeout = TimeSpan.FromSeconds(15);

    /// <summary>Expected byte length of the Challenge payload (Requirement 5.2).</summary>
    public const int ChallengeByteLength = 57;

    // -------------------------------------------------------------------------
    // Fields
    // -------------------------------------------------------------------------

    private readonly ILogger _logger;
    private BluetoothLEAdvertisementWatcher? _watcher;
    private volatile bool _disposed;

    // -------------------------------------------------------------------------
    // Construction
    // -------------------------------------------------------------------------

    /// <summary>
    /// Creates a new <see cref="BLECentral"/> instance.
    /// </summary>
    /// <param name="logger">Logger for diagnostic and security events.</param>
    public BLECentral(ILogger logger)
    {
        _logger = logger ?? throw new ArgumentNullException(nameof(logger));
    }

    // -------------------------------------------------------------------------
    // IBLECentral
    // -------------------------------------------------------------------------

    /// <inheritdoc/>
    public async Task<BLESessionResult> RunSessionAsync(
        byte[] challengeBytes,
        CancellationToken cancellationToken = default)
    {
        ObjectDisposedException.ThrowIf(_disposed, this);

        if (challengeBytes is null || challengeBytes.Length != ChallengeByteLength)
        {
            return BLESessionResult.Failed(
                $"Challenge must be exactly {ChallengeByteLength} bytes; " +
                $"received {challengeBytes?.Length ?? 0} bytes.");
        }

        // Enforce the 15-second session timeout (Requirement 4.6).
        // Link the external token so either side can cancel.
        using var sessionCts = CancellationTokenSource.CreateLinkedTokenSource(
            cancellationToken);
        sessionCts.CancelAfter(SessionTimeout);
        var sessionToken = sessionCts.Token;

        _logger.Log(LogLevel.Information,
            "BLECentral: starting scan for PCUnlock peripheral.");

        ulong? foundAddress = null;
        using var deviceFoundSemaphore = new SemaphoreSlim(0, 1);

        // -----------------------------------------------------------------------
        // Phase 1: Scan for a peripheral advertising the PCUnlock service UUID
        //          (Requirement 4.1)
        // -----------------------------------------------------------------------
        var watcher = new BluetoothLEAdvertisementWatcher();
        _watcher = watcher;

        // Filter to only advertisements that include our service UUID.
        watcher.AdvertisementFilter.Advertisement.ServiceUuids.Add(ServiceUuid);
        watcher.ScanningMode = BluetoothLEScanningMode.Active;

        void OnAdvertisementReceived(
            BluetoothLEAdvertisementWatcher sender,
            BluetoothLEAdvertisementReceivedEventArgs args)
        {
            if (foundAddress.HasValue)
                return; // Already found one; ignore subsequent hits.

            foundAddress = args.BluetoothAddress;
            _logger.Log(LogLevel.Information,
                $"BLECentral: peripheral found at address {args.BluetoothAddress:X12}.");

            // Unblock the awaiting code.
            try { deviceFoundSemaphore.Release(); } catch { /* already released */ }
        }

        watcher.Received += OnAdvertisementReceived;
        watcher.Start();

        try
        {
            // Wait for a peripheral to be found, or time out.
            bool signalled = await WaitForSemaphoreAsync(deviceFoundSemaphore, sessionToken);
            if (!signalled || !foundAddress.HasValue)
            {
                _logger.Log(LogLevel.Warning,
                    "BLECentral: session timed out waiting for peripheral advertisement.");
                return BLESessionResult.TimedOut();
            }
        }
        catch (OperationCanceledException)
        {
            // Distinguish external cancel from internal 15-s timeout.
            if (cancellationToken.IsCancellationRequested)
            {
                _logger.Log(LogLevel.Information,
                    "BLECentral: scan cancelled by caller.");
            }
            else
            {
                _logger.Log(LogLevel.Warning,
                    "BLECentral: 15-second timeout elapsed before peripheral found.");
            }
            return BLESessionResult.TimedOut();
        }
        finally
        {
            watcher.Received -= OnAdvertisementReceived;
            StopWatcher(watcher);
            _watcher = null;
        }

        // -----------------------------------------------------------------------
        // Phase 2: Connect and run GATT exchange
        //          (Requirements 4.3, 4.6)
        // -----------------------------------------------------------------------
        return await RunGattExchangeAsync(
            foundAddress!.Value, challengeBytes, sessionToken, cancellationToken);
    }

    /// <inheritdoc/>
    public void StopScan()
    {
        var watcher = _watcher;
        if (watcher is not null)
            StopWatcher(watcher);
    }

    // -------------------------------------------------------------------------
    // GATT Exchange
    // -------------------------------------------------------------------------

    /// <summary>
    /// Connects to the peripheral at <paramref name="bluetoothAddress"/> and
    /// performs the three-step GATT exchange.
    /// </summary>
    private async Task<BLESessionResult> RunGattExchangeAsync(
        ulong bluetoothAddress,
        byte[] challengeBytes,
        CancellationToken sessionToken,
        CancellationToken externalToken)
    {
        BluetoothLEDevice? device = null;
        GattSession? gattSession = null;

        try
        {
            sessionToken.ThrowIfCancellationRequested();

            // Connect (Requirement 4.1 — central establishes connection).
            device = await BluetoothLEDevice
                .FromBluetoothAddressAsync(bluetoothAddress)
                .AsTask(sessionToken);

            if (device is null)
            {
                _logger.Log(LogLevel.Warning,
                    "BLECentral: BluetoothLEDevice.FromBluetoothAddressAsync returned null.");
                return BLESessionResult.Failed("Could not create BLE device object.");
            }

            // Request a persistent GATT session so the OS maintains the connection.
            var deviceId = BluetoothDeviceId.FromId(device.DeviceId);
            gattSession = await GattSession
                .FromDeviceIdAsync(deviceId)
                .AsTask(sessionToken);

            if (gattSession is null)
            {
                return BLESessionResult.Failed("Could not establish GATT session.");
            }

            // Maintain the connection for the duration of this session.
            gattSession.MaintainConnection = true;

            // Retrieve the PCUnlock GATT service.
            var servicesResult = await device
                .GetGattServicesForUuidAsync(ServiceUuid,
                    BluetoothCacheMode.Uncached)
                .AsTask(sessionToken);

            if (servicesResult.Status != GattCommunicationStatus.Success ||
                servicesResult.Services.Count == 0)
            {
                _logger.Log(LogLevel.Warning,
                    $"BLECentral: PCUnlock GATT service not found on device " +
                    $"(status={servicesResult.Status}).");
                return BLESessionResult.Failed(
                    $"GATT service not found: {servicesResult.Status}");
            }

            using var service = servicesResult.Services[0];

            // ------------------------------------------------------------------
            // Step 1: Read DeviceAdvData characteristic to identify device
            //         (Requirement 4.1 — "read DeviceAdvData characteristic")
            // ------------------------------------------------------------------
            var deviceIdBytes = await ReadDeviceAdvDataAsync(service, sessionToken);
            if (deviceIdBytes is null)
            {
                return BLESessionResult.Failed(
                    "Failed to read DeviceAdvData characteristic.");
            }

            _logger.Log(LogLevel.Information,
                $"BLECentral: device identified ({BitConverter.ToString(deviceIdBytes)}).");

            // ------------------------------------------------------------------
            // Step 2: Subscribe to Response characteristic BEFORE writing the
            //         Challenge, to avoid missing the notification.
            //         (Requirement 4.3 — await notify on Response characteristic)
            // ------------------------------------------------------------------
            var responseChar = await GetCharacteristicAsync(
                service, ResponseCharacteristicUuid, sessionToken);
            if (responseChar is null)
            {
                return BLESessionResult.Failed(
                    "Response characteristic not found.");
            }

            using var responseReceived = new SemaphoreSlim(0, 1);
            byte[]? responseBytes = null;

            void OnValueChanged(
                GattCharacteristic sender,
                GattValueChangedEventArgs args)
            {
                responseBytes = args.CharacteristicValue.ToArray();
                _logger.Log(LogLevel.Information,
                    $"BLECentral: Response notification received " +
                    $"({responseBytes.Length} bytes).");
                try { responseReceived.Release(); } catch { /* already released */ }
            }

            responseChar.ValueChanged += OnValueChanged;

            // Enable notifications on the Response characteristic
            // (Requirement: GattClientCharacteristicConfigurationDescriptorValue.Notify).
            var notifyStatus = await responseChar
                .WriteClientCharacteristicConfigurationDescriptorAsync(
                    GattClientCharacteristicConfigurationDescriptorValue.Notify)
                .AsTask(sessionToken);

            if (notifyStatus != GattCommunicationStatus.Success)
            {
                responseChar.ValueChanged -= OnValueChanged;
                return BLESessionResult.Failed(
                    $"Failed to enable Response notifications: {notifyStatus}");
            }

            try
            {
                // --------------------------------------------------------------
                // Step 3: Write Challenge to Challenge characteristic
                //         (Requirement 4.3)
                // --------------------------------------------------------------
                var writeResult = await WriteChallengeAsync(
                    service, challengeBytes, sessionToken);
                if (!writeResult)
                {
                    return BLESessionResult.Failed(
                        "Failed to write Challenge characteristic.");
                }

                _logger.Log(LogLevel.Information,
                    "BLECentral: Challenge written; awaiting Response notification.");

                // --------------------------------------------------------------
                // Step 4: Await the Response notification (still within the
                //         15-second session window).
                // --------------------------------------------------------------
                bool notified = await WaitForSemaphoreAsync(
                    responseReceived, sessionToken);

                if (!notified || responseBytes is null)
                {
                    _logger.Log(LogLevel.Warning,
                        "BLECentral: timed out waiting for Response notification.");
                    return BLESessionResult.TimedOut();
                }
            }
            catch (OperationCanceledException)
            {
                bool isTimeout = !externalToken.IsCancellationRequested;
                _logger.Log(LogLevel.Warning,
                    isTimeout
                        ? "BLECentral: 15-second timeout during GATT exchange."
                        : "BLECentral: GATT exchange cancelled by caller.");
                return BLESessionResult.TimedOut();
            }
            finally
            {
                responseChar.ValueChanged -= OnValueChanged;

                // Disable notifications (best effort — session is ending).
                try
                {
                    await responseChar
                        .WriteClientCharacteristicConfigurationDescriptorAsync(
                            GattClientCharacteristicConfigurationDescriptorValue.None)
                        .AsTask(CancellationToken.None);
                }
                catch { /* Ignore errors during teardown */ }
            }

            return BLESessionResult.Succeeded(responseBytes!, deviceIdBytes);
        }
        catch (OperationCanceledException)
        {
            bool isTimeout = !externalToken.IsCancellationRequested;
            _logger.Log(LogLevel.Warning,
                isTimeout
                    ? "BLECentral: 15-second timeout during device connection."
                    : "BLECentral: connection cancelled by caller.");
            return BLESessionResult.TimedOut();
        }
        catch (Exception ex) when (ex is not OutOfMemoryException)
        {
            _logger.Log(LogLevel.Error,
                $"BLECentral: unexpected error during GATT exchange: {ex.Message}");
            return BLESessionResult.Failed(ex.Message);
        }
        finally
        {
            gattSession?.Dispose();
            device?.Dispose();
        }
    }

    // -------------------------------------------------------------------------
    // Characteristic helpers
    // -------------------------------------------------------------------------

    /// <summary>
    /// Reads the DeviceAdvData characteristic (UUID …7894) and returns the raw
    /// bytes, or <c>null</c> on failure.
    /// </summary>
    private static async Task<byte[]?> ReadDeviceAdvDataAsync(
        GattDeviceService service,
        CancellationToken token)
    {
        var characteristic = await GetCharacteristicAsync(
            service, DeviceAdvDataCharacteristicUuid, token);
        if (characteristic is null)
            return null;

        var readResult = await characteristic
            .ReadValueAsync(BluetoothCacheMode.Uncached)
            .AsTask(token);

        if (readResult.Status != GattCommunicationStatus.Success)
            return null;

        return readResult.Value.ToArray();
    }

    /// <summary>
    /// Writes <paramref name="challengeBytes"/> to the Challenge characteristic
    /// (UUID …7891).  Returns <c>true</c> on success.
    /// </summary>
    private static async Task<bool> WriteChallengeAsync(
        GattDeviceService service,
        byte[] challengeBytes,
        CancellationToken token)
    {
        var characteristic = await GetCharacteristicAsync(
            service, ChallengeCharacteristicUuid, token);
        if (characteristic is null)
            return false;

        using var writer = new DataWriter();
        writer.WriteBytes(challengeBytes);
        var buffer = writer.DetachBuffer();

        var writeStatus = await characteristic
            .WriteValueWithResultAsync(buffer, GattWriteOption.WriteWithResponse)
            .AsTask(token);

        return writeStatus.Status == GattCommunicationStatus.Success;
    }

    /// <summary>
    /// Retrieves the first characteristic matching <paramref name="uuid"/>
    /// from <paramref name="service"/>, or <c>null</c> if not found.
    /// </summary>
    private static async Task<GattCharacteristic?> GetCharacteristicAsync(
        GattDeviceService service,
        Guid uuid,
        CancellationToken token)
    {
        var result = await service
            .GetCharacteristicsForUuidAsync(uuid, BluetoothCacheMode.Uncached)
            .AsTask(token);

        if (result.Status != GattCommunicationStatus.Success ||
            result.Characteristics.Count == 0)
        {
            return null;
        }

        return result.Characteristics[0];
    }

    // -------------------------------------------------------------------------
    // Utility
    // -------------------------------------------------------------------------

    /// <summary>
    /// Waits asynchronously for a <see cref="SemaphoreSlim"/> to be released,
    /// respecting <paramref name="token"/>.
    /// </summary>
    /// <returns>
    /// <c>true</c> if the semaphore was released; <c>false</c> if the token
    /// was cancelled before the semaphore was released.
    /// </returns>
    private static async Task<bool> WaitForSemaphoreAsync(
        SemaphoreSlim semaphore,
        CancellationToken token)
    {
        try
        {
            await semaphore.WaitAsync(token);
            return true;
        }
        catch (OperationCanceledException)
        {
            return false;
        }
    }

    private static void StopWatcher(BluetoothLEAdvertisementWatcher watcher)
    {
        try
        {
            if (watcher.Status == BluetoothLEAdvertisementWatcherStatus.Started)
                watcher.Stop();
        }
        catch { /* Ignore stop errors */ }
    }

    // -------------------------------------------------------------------------
    // IDisposable
    // -------------------------------------------------------------------------

    /// <inheritdoc/>
    public void Dispose()
    {
        if (_disposed)
            return;
        _disposed = true;
        StopScan();
    }
}
