// Feature: pc-unlock
// BLESessionResult — typed result returned by BLECentral after an unlock attempt.
// Requirements: 4.1, 4.3, 4.6

namespace PCUnlockService.BLE;

/// <summary>
/// Describes the outcome of a single BLE unlock session.
/// </summary>
public enum BLESessionStatus
{
    /// <summary>
    /// The session completed successfully and a Response was received.
    /// </summary>
    Success,

    /// <summary>
    /// No peripheral was found or the connection was not established within
    /// the 15-second timeout window (Requirement 4.6).
    /// </summary>
    Timeout,

    /// <summary>
    /// A device was found but it is not present in the Device Registry
    /// (unrecognised <c>deviceId</c> read from the DeviceAdvData characteristic).
    /// </summary>
    UnknownDevice,

    /// <summary>
    /// A BLE API or GATT error occurred during the session.
    /// </summary>
    Error,
}

/// <summary>
/// The result of a BLE unlock session, returned by
/// <see cref="IBLECentral.RunSessionAsync"/>.
/// </summary>
public sealed class BLESessionResult
{
    /// <summary>Outcome of the session.</summary>
    public BLESessionStatus Status { get; }

    /// <summary>
    /// The raw Response bytes received from the peripheral's Response
    /// characteristic notification.  Non-null only when
    /// <see cref="Status"/> is <see cref="BLESessionStatus.Success"/>.
    /// </summary>
    public byte[]? ResponseBytes { get; }

    /// <summary>
    /// The <c>deviceId</c> UUID bytes (16 bytes) read from the
    /// DeviceAdvData characteristic.  Available when
    /// <see cref="Status"/> is <see cref="BLESessionStatus.Success"/> or
    /// <see cref="BLESessionStatus.UnknownDevice"/>.
    /// </summary>
    public byte[]? DeviceId { get; }

    /// <summary>
    /// Optional human-readable description of an error or timeout cause.
    /// </summary>
    public string? ErrorMessage { get; }

    private BLESessionResult(
        BLESessionStatus status,
        byte[]? responseBytes,
        byte[]? deviceId,
        string? errorMessage)
    {
        Status = status;
        ResponseBytes = responseBytes;
        DeviceId = deviceId;
        ErrorMessage = errorMessage;
    }

    // -------------------------------------------------------------------------
    // Factory helpers
    // -------------------------------------------------------------------------

    /// <summary>Creates a successful result carrying the raw Response bytes.</summary>
    public static BLESessionResult Succeeded(byte[] responseBytes, byte[] deviceId)
        => new(BLESessionStatus.Success, responseBytes, deviceId, null);

    /// <summary>Creates a timeout result (Requirement 4.6).</summary>
    public static BLESessionResult TimedOut()
        => new(BLESessionStatus.Timeout, null, null, "BLE connection attempt exceeded 15-second timeout.");

    /// <summary>Creates an unknown-device result.</summary>
    public static BLESessionResult DeviceNotRecognised(byte[] deviceId)
        => new(BLESessionStatus.UnknownDevice, null, deviceId, "Device identifier not found in Device Registry.");

    /// <summary>Creates an error result.</summary>
    public static BLESessionResult Failed(string message)
        => new(BLESessionStatus.Error, null, null, message);
}
