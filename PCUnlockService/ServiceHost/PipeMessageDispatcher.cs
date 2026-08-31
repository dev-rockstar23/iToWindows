// Feature: pc-unlock
// PipeMessageDispatcher — routes Named Pipe messages to the correct service component.
// Requirements: 7.3, 8.1, 8.2, 8.3

using System.Text.Json;
using Microsoft.Extensions.Logging;
using PCUnlockService.BLE;
using PCUnlockService.Crypto;
using PCUnlockService.Logging;
using PCUnlockService.Pairing;
using PCUnlockService.Pipe;
using PCUnlockService.Registry;
using PCUnlockService.Session;

namespace PCUnlockService.ServiceHost;

/// <summary>
/// Implements <see cref="IPipeMessageHandler"/> by dispatching each message
/// type to the appropriate service component.
/// </summary>
public sealed class PipeMessageDispatcher : IPipeMessageHandler
{
    private readonly ISessionNonceManager   _sessionManager;
    private readonly ICNGCryptoVerifier     _cryptoVerifier;
    private readonly IConsumedNonceStore    _nonceStore;
    private readonly IDeviceRegistry        _deviceRegistry;
    private readonly ISecurityLogger        _securityLogger;
    private readonly IBLECentral            _bleCentral;
    private readonly ILogger<PipeMessageDispatcher> _logger;

    public PipeMessageDispatcher(
        ISessionNonceManager   sessionManager,
        ICNGCryptoVerifier     cryptoVerifier,
        IConsumedNonceStore    nonceStore,
        IDeviceRegistry        deviceRegistry,
        ISecurityLogger        securityLogger,
        IBLECentral            bleCentral,
        ILogger<PipeMessageDispatcher> logger)
    {
        _sessionManager = sessionManager;
        _cryptoVerifier = cryptoVerifier;
        _nonceStore     = nonceStore;
        _deviceRegistry = deviceRegistry;
        _securityLogger = securityLogger;
        _bleCentral     = bleCentral;
        _logger         = logger;
    }

    /// <inheritdoc/>
    public async Task<object?> HandleAsync(
        string messageType,
        string jsonPayload,
        CancellationToken ct)
    {
        return messageType switch
        {
            "unlock_request"  => await HandleUnlockRequestAsync(jsonPayload, ct),
            "remove_device"   => HandleRemoveDevice(jsonPayload),
            "list_devices"    => HandleListDevices(),
            _                 => HandleUnknown(messageType)
        };
    }

    // -------------------------------------------------------------------------
    // Handlers
    // -------------------------------------------------------------------------

    private async Task<UnlockResponse> HandleUnlockRequestAsync(
        string json, CancellationToken ct)
    {
        UnlockRequest? request;
        try
        {
            request = JsonSerializer.Deserialize<UnlockRequest>(json);
        }
        catch
        {
            return new UnlockResponse { Result = "failure", Reason = "MALFORMED_REQUEST" };
        }

        if (request is null)
            return new UnlockResponse { Result = "failure", Reason = "MALFORMED_REQUEST" };

        // Verify Device Registry integrity before processing.
        if (!_deviceRegistry.VerifyIntegrity())
        {
            _logger.LogError("Unlock request rejected: Device Registry integrity check failed.");
            _securityLogger.LogUnlockAttempt(request.UserId, "failure", "REGISTRY_CORRUPT");
            return new UnlockResponse { Result = "failure", Reason = "REGISTRY_CORRUPT" };
        }

        // Start a session — generates challenge.
        var session  = _sessionManager.StartSession(request.UserId);
        var challenge = ChallengeGenerator.EncodeChallenge(session);

        // Run the BLE exchange to get the Response bytes.
        var bleResult = await _bleCentral.RunSessionAsync(challenge, ct).ConfigureAwait(false);

        if (bleResult.Status == BLESessionStatus.Timeout)
        {
            _sessionManager.ClearSession();
            _securityLogger.LogUnlockAttempt(request.UserId, "failure", "TIMEOUT");
            return new UnlockResponse { Result = "timeout", Reason = "TIMEOUT" };
        }

        if (bleResult.Status != BLESessionStatus.Success || bleResult.ResponseBytes is null)
        {
            _sessionManager.ClearSession();
            _securityLogger.LogUnlockAttempt(request.UserId, "failure", "BLE_ERROR");
            return new UnlockResponse { Result = "failure", Reason = "BLE_ERROR" };
        }

        // Parse the BLE Response to extract sessionId, deviceId, signature.
        BleResponse? bleResponse = ParseBleResponse(bleResult.ResponseBytes);
        if (bleResponse is null)
        {
            _sessionManager.ClearSession();
            _securityLogger.LogUnlockAttempt(request.UserId, "failure", "MALFORMED_RESPONSE");
            return new UnlockResponse { Result = "failure", Reason = "MALFORMED_RESPONSE" };
        }

        // Pre-signature validation (expiry, nonce replay, session ID match).
        var validationResult = _sessionManager.ValidateResponse(bleResponse);
        if (!validationResult.IsValid)
        {
            _sessionManager.ClearSession();
            string reason = validationResult.Reason.ToString().ToUpperInvariant();
            _securityLogger.LogUnlockAttempt(request.UserId, "failure", reason);
            if (validationResult.Reason == ResponseRejectionReason.ReplayedNonce)
                _securityLogger.LogNonceRejection(session.SessionId.ToString(), "REPLAY");
            return new UnlockResponse { Result = "failure", Reason = reason };
        }

        // Look up device record for the crypto verifier.
        var deviceRecord = _deviceRegistry.Get(bleResponse.DeviceId);
        if (deviceRecord is null)
        {
            _sessionManager.ClearSession();
            _securityLogger.LogUnlockAttempt(request.UserId, "failure", "UNKNOWN_DEVICE");
            return new UnlockResponse { Result = "failure", Reason = "UNKNOWN_DEVICE" };
        }

        // CNG signature verification.
        var cryptoResult = _cryptoVerifier.Verify(
            deviceRecord.PublicKeyDER,
            challenge,
            bleResponse.SignatureDER);

        if (cryptoResult.Outcome != VerificationOutcome.Success)
        {
            _sessionManager.ClearSession();
            string reason = cryptoResult.Outcome.ToString().ToUpperInvariant();
            _securityLogger.LogUnlockAttempt(
                bleResponse.DeviceId.ToString(), "failure", reason);
            return new UnlockResponse { Result = "failure", Reason = reason };
        }

        // Persist nonce BEFORE signalling success (Requirement 13.4).
        _nonceStore.Append(session.Nonce);
        _sessionManager.ClearSession();

        _securityLogger.LogUnlockAttempt(bleResponse.DeviceId.ToString(), "success");
        return new UnlockResponse { Result = "success" };
    }

    private RemoveDeviceResponse HandleRemoveDevice(string json)
    {
        RemoveDeviceRequest? request;
        try { request = JsonSerializer.Deserialize<RemoveDeviceRequest>(json); }
        catch { return new RemoveDeviceResponse { Ok = false, Error = "MALFORMED_REQUEST" }; }

        if (request is null || !Guid.TryParse(request.DeviceId, out var deviceId))
            return new RemoveDeviceResponse { Ok = false, Error = "INVALID_DEVICE_ID" };

        try
        {
            _deviceRegistry.Remove(deviceId);
            _securityLogger.LogPairingEvent(deviceId.ToString(), "device_removed");
            return new RemoveDeviceResponse { Ok = true };
        }
        catch (Registry.DeviceRegistryException ex)
        {
            return new RemoveDeviceResponse { Ok = false, Error = ex.Message };
        }
    }

    private ListDevicesResponse HandleListDevices()
    {
        var devices = _deviceRegistry.ReadAll();
        return new ListDevicesResponse { Devices = devices.ToArray() };
    }

    private object? HandleUnknown(string type)
    {
        _logger.LogWarning("PipeMessageDispatcher: unknown message type '{Type}'.", type);
        return null;
    }

    // -------------------------------------------------------------------------
    // Helpers
    // -------------------------------------------------------------------------

    /// <summary>
    /// Parses the raw BLE Response bytes into a <see cref="BleResponse"/>.
    /// Wire layout: [version:1][sessionId:16][deviceId:16][signatureDER:variable]
    /// </summary>
    private static BleResponse? ParseBleResponse(byte[] bytes)
    {
        if (bytes.Length < 33) return null; // minimum: version + sessionId + deviceId

        try
        {
            byte version = bytes[0];
            var sessionId = new Guid(bytes[1..17]);
            var deviceId  = new Guid(bytes[17..33]);
            var signature = bytes[33..];

            return new BleResponse
            {
                Version      = version,
                SessionId    = sessionId,
                DeviceId     = deviceId,
                SignatureDER = signature,
            };
        }
        catch
        {
            return null;
        }
    }
}
