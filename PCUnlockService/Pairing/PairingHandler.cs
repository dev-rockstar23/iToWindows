// Feature: pc-unlock
// PairingHandler — orchestrates the PC side of the QR pairing flow.
// Requirements: 6.1, 6.2, 6.5, 6.6, 10.2

using System.Security.Cryptography;
using System.Text.Json;
using Microsoft.Extensions.Logging;

namespace PCUnlockService.Pairing;

/// <summary>
/// Implements <see cref="IPairingHandler"/> — runs the full PC-side pairing
/// flow: generate identity material → display QR → await iPhone → verify code
/// → commit <see cref="DeviceRecord"/> → notify iPhone.
/// </summary>
/// <remarks>
/// All intermediate state is discarded on timeout, code mismatch, or
/// external cancellation (Requirement 6.6).
/// </remarks>
public sealed class PairingHandler : IPairingHandler
{
    // -------------------------------------------------------------------------
    // Constants
    // -------------------------------------------------------------------------

    /// <summary>
    /// BLE service UUID used by the PCUnlock GATT service.
    /// Encoded into the QR payload so the iPhone knows which service to connect to.
    /// </summary>
    private static readonly Guid BleServiceUuid =
        new("A1B2C3D4-E5F6-7890-ABCD-EF1234567890");

    /// <summary>Pairing timeout from Requirement 6.6.</summary>
    private const int PairingTimeoutSeconds = 120;

    /// <summary>
    /// Alphabet for generating the 6-character alphanumeric Pairing_Code.
    /// Uppercase letters A-Z and digits 0-9 — 36 characters total.
    /// </summary>
    private const string PairingCodeAlphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";

    // -------------------------------------------------------------------------
    // Dependencies
    // -------------------------------------------------------------------------

    private readonly IBLEPairingChannel _bleChannel;
    private readonly ILogger<PairingHandler> _logger;

    /// <summary>
    /// Initialises a new <see cref="PairingHandler"/>.
    /// </summary>
    /// <param name="bleChannel">
    ///   The BLE abstraction that delivers the iPhone's <see cref="PairingRequest"/>
    ///   and sends the completion acknowledgement.
    /// </param>
    /// <param name="logger">Logger for pairing events (Requirement 10.2).</param>
    public PairingHandler(IBLEPairingChannel bleChannel, ILogger<PairingHandler> logger)
    {
        _bleChannel = bleChannel ?? throw new ArgumentNullException(nameof(bleChannel));
        _logger     = logger     ?? throw new ArgumentNullException(nameof(logger));
    }

    // -------------------------------------------------------------------------
    // IPairingHandler
    // -------------------------------------------------------------------------

    /// <inheritdoc />
    public async Task<PairingResult> StartPairingAsync(
        string deviceName,
        CancellationToken ct = default)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(deviceName);

        // ------------------------------------------------------------------
        // Step 1 — Generate 16-byte pcIdentityToken (Requirement 6.1).
        //          BCryptGenRandom is exposed as RandomNumberGenerator.GetBytes
        //          in .NET (wraps CNG internally).
        // ------------------------------------------------------------------
        byte[] pcIdentityToken = RandomNumberGenerator.GetBytes(16);

        // ------------------------------------------------------------------
        // Step 2 — Generate 6-char alphanumeric Pairing_Code (Req 6.1).
        //          Use RandomNumberGenerator for unbiased selection.
        // ------------------------------------------------------------------
        string pairingCode = GeneratePairingCode();

        // ------------------------------------------------------------------
        // Step 3 — Create PairingSession (transient, in-memory only).
        // ------------------------------------------------------------------
        var session = PairingSession.Create(
            pairingCode,
            pcIdentityToken,
            DateTimeOffset.UtcNow);

        try
        {
            // --------------------------------------------------------------
            // Step 4 — Encode PairingPayload as JSON; stub QR rendering.
            // --------------------------------------------------------------
            var payload = PairingPayload.Create(pcIdentityToken, pairingCode, BleServiceUuid);
            string payloadJson = JsonSerializer.Serialize(payload, new JsonSerializerOptions
            {
                PropertyNamingPolicy = null, // property names already set via JsonPropertyName
            });

            _logger.LogInformation(
                "Pairing session {SessionId} started. PairingPayload JSON: {Json}",
                session.SessionId,
                payloadJson);

            // TODO: Render QR code via QRCoder NuGet package.
            //       Example (not yet wired in):
            //
            //   using QRCoder;
            //   var qrGenerator = new QRCodeGenerator();
            //   var qrData = qrGenerator.CreateQrCode(payloadJson, QRCodeGenerator.ECCLevel.M);
            //   // hand qrData to the UI layer for rendering
            //
            // For now, return the raw JSON so the caller can display/log it.
            string qrStub = payloadJson; // stub — replace with QRCoder output
            _ = qrStub;                  // suppress unused-variable warning until QRCoder is wired in

            // --------------------------------------------------------------
            // Step 5 — Create a CancellationTokenSource linked to the caller's
            //          token AND the 120-second hard timeout (Requirement 6.6).
            // --------------------------------------------------------------
            using var cts = CancellationTokenSource.CreateLinkedTokenSource(ct);
            cts.CancelAfter(TimeSpan.FromSeconds(PairingTimeoutSeconds));

            // --------------------------------------------------------------
            // Step 6 — Await BLE PairingRequest from iPhone.
            // --------------------------------------------------------------
            PairingRequest? request;
            try
            {
                request = await _bleChannel.AwaitPairingRequestAsync(cts.Token)
                                           .ConfigureAwait(false);
            }
            catch (OperationCanceledException)
            {
                request = null;
            }

            // --------------------------------------------------------------
            // Step 7 — Handle timeout / cancellation.
            // --------------------------------------------------------------
            if (request is null)
            {
                session.ClearSensitiveData();
                session.State = PairingSessionState.Cancelled;

                _logger.LogWarning(
                    "Pairing session {SessionId} timed out or was cancelled — all intermediate state discarded.",
                    session.SessionId);

                // Distinguish external cancellation from hard timeout.
                // If the caller's token was signalled before our timeout fired,
                // the caller deliberately cancelled; otherwise it was a timeout.
                return ct.IsCancellationRequested
                    ? PairingResult.Cancelled()
                    : PairingResult.Timeout();
            }

            // --------------------------------------------------------------
            // Step 8 — Verify Pairing_Code echo (case-insensitive).
            // --------------------------------------------------------------
            if (!string.Equals(request.PairingCodeEcho, session.PairingCode,
                                StringComparison.OrdinalIgnoreCase))
            {
                session.ClearSensitiveData();
                session.State = PairingSessionState.Cancelled;

                _logger.LogWarning(
                    "Pairing session {SessionId} failed: Pairing_Code mismatch " +
                    "(expected '{Expected}', received '{Received}').",
                    session.SessionId,
                    session.PairingCode,
                    request.PairingCodeEcho);

                return PairingResult.CodeMismatch();
            }

            // Store pending public key in session for clarity (not strictly
            // necessary since we use it immediately below, but mirrors the
            // PairingSession design contract).
            session.PendingPublicKey = request.PublicKeyDER;
            session.State = PairingSessionState.PendingConfirmation;

            // --------------------------------------------------------------
            // Step 9 — Build DeviceRecord from verified session data.
            // --------------------------------------------------------------
            var deviceRecord = new DeviceRecord
            {
                DeviceId        = Guid.NewGuid(),
                DeviceName      = deviceName,
                PublicKeyDER    = request.PublicKeyDER,
                PairedAt        = DateTimeOffset.UtcNow,
                LastUsedAt      = null,
                PcIdentityToken = session.PcIdentityToken,
            };

            // --------------------------------------------------------------
            // Step 10 — Send PairingComplete notification to iPhone (best effort).
            //           Use CancellationToken.None so a late cancellation from
            //           the caller does not prevent the acknowledgement.
            // --------------------------------------------------------------
            try
            {
                await _bleChannel.SendPairingCompleteAsync(CancellationToken.None)
                                  .ConfigureAwait(false);
            }
            catch (Exception ex)
            {
                // Best-effort only; log but do not fail the pairing.
                _logger.LogWarning(ex,
                    "Pairing session {SessionId}: failed to send PairingComplete notification — " +
                    "device record was committed anyway.",
                    session.SessionId);
            }

            // --------------------------------------------------------------
            // Step 11 — Clear session state and return success.
            // --------------------------------------------------------------
            session.ClearSensitiveData();
            session.State = PairingSessionState.Complete;

            _logger.LogInformation(
                "Pairing session {SessionId} completed successfully. " +
                "DeviceId={DeviceId} DeviceName='{DeviceName}'.",
                session.SessionId,
                deviceRecord.DeviceId,
                deviceRecord.DeviceName);

            return PairingResult.Success(deviceRecord);
        }
        catch (Exception ex) when (ex is not OperationCanceledException)
        {
            // Unexpected failure — clear sensitive state before propagating.
            session.ClearSensitiveData();
            session.State = PairingSessionState.Cancelled;

            _logger.LogError(ex,
                "Pairing session {SessionId} failed with an unexpected error.",
                session.SessionId);

            throw;
        }
    }

    // -------------------------------------------------------------------------
    // Helpers
    // -------------------------------------------------------------------------

    /// <summary>
    /// Generates a 6-character uppercase alphanumeric Pairing_Code using
    /// <see cref="RandomNumberGenerator"/> for unbiased selection (no modulo
    /// bias: rejection sampling ensures uniform distribution over the 36-char
    /// alphabet).
    /// </summary>
    private static string GeneratePairingCode()
    {
        const int CodeLength = 6;
        int alphabetLen = PairingCodeAlphabet.Length; // 36

        // Find the largest multiple of alphabetLen that fits in a byte (0–255)
        // to avoid modulo bias.
        int maxUnbiased = (256 / alphabetLen) * alphabetLen; // 252

        Span<char> code   = stackalloc char[CodeLength];
        Span<byte> buffer = stackalloc byte[1];
        int filled = 0;

        while (filled < CodeLength)
        {
            RandomNumberGenerator.Fill(buffer);
            byte b = buffer[0];
            if (b < maxUnbiased)
            {
                code[filled++] = PairingCodeAlphabet[b % alphabetLen];
            }
            // else discard and retry (rejection sampling)
        }

        return new string(code);
    }
}
