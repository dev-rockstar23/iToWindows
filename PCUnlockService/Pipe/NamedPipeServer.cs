// Feature: pc-unlock
// NamedPipeServer — creates \\.\pipe\PCUnlockService and processes IPC messages.
// Requirements: 7.3, 8.1, 8.2, 8.7

using System.IO.Pipes;
using System.Text;
using System.Text.Json;
using Microsoft.Extensions.Logging;

namespace PCUnlockService.Pipe;

/// <summary>
/// Creates <c>\\.\pipe\PCUnlockService</c> and processes framed JSON messages
/// from the Credential Provider and Management UI.
/// </summary>
/// <remarks>
/// Message framing: 4-byte little-endian uint32 length prefix + UTF-8 JSON body.
/// Maximum message size: 64 KB (Requirement 8.7). Messages larger than 64 KB cause
/// the connection to be closed immediately.
/// </remarks>
public sealed class NamedPipeServer
{
    private const string PipeName   = "PCUnlockService";
    private const int    MaxMsgSize = 64 * 1024; // 64 KB

    private readonly IPipeMessageHandler         _handler;
    private readonly ILogger<NamedPipeServer>    _logger;
    private          CancellationTokenSource?    _cts;

    /// <summary>
    /// Creates a <see cref="NamedPipeServer"/>.
    /// </summary>
    public NamedPipeServer(IPipeMessageHandler handler, ILogger<NamedPipeServer> logger)
    {
        _handler = handler ?? throw new ArgumentNullException(nameof(handler));
        _logger  = logger  ?? throw new ArgumentNullException(nameof(logger));
    }

    /// <summary>
    /// Starts accepting connections until <paramref name="ct"/> is cancelled.
    /// </summary>
    public async Task StartAsync(CancellationToken ct = default)
    {
        _cts = CancellationTokenSource.CreateLinkedTokenSource(ct);
        var token = _cts.Token;

        _logger.LogInformation("NamedPipeServer: starting on \\\\.\\pipe\\{PipeName}", PipeName);

        while (!token.IsCancellationRequested)
        {
            NamedPipeServerStream? pipe = null;
            try
            {
                // Build pipe with PipeSecurity granting ReadWrite to Admins + LocalSystem.
                // Full per-SID DACL (CP process SID, management tool SID) is wired in Phase 5.9.
                var security = new PipeSecurity();
                security.AddAccessRule(new PipeAccessRule(
                    new System.Security.Principal.SecurityIdentifier(
                        System.Security.Principal.WellKnownSidType.BuiltinAdministratorsSid, null),
                    PipeAccessRights.ReadWrite,
                    System.Security.AccessControl.AccessControlType.Allow));
                security.AddAccessRule(new PipeAccessRule(
                    new System.Security.Principal.SecurityIdentifier(
                        System.Security.Principal.WellKnownSidType.LocalSystemSid, null),
                    PipeAccessRights.ReadWrite,
                    System.Security.AccessControl.AccessControlType.Allow));

                pipe = NamedPipeServerStreamAcl.Create(
                    PipeName,
                    PipeDirection.InOut,
                    maxNumberOfServerInstances: 1,
                    PipeTransmissionMode.Byte,
                    PipeOptions.Asynchronous,
                    inBufferSize: 0,
                    outBufferSize: 0,
                    security);

                await pipe.WaitForConnectionAsync(token).ConfigureAwait(false);
                _logger.LogInformation("NamedPipeServer: client connected.");

                await HandleConnectionAsync(pipe, token).ConfigureAwait(false);
            }
            catch (OperationCanceledException)
            {
                break;
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "NamedPipeServer: error accepting connection.");
            }
            finally
            {
                pipe?.Dispose();
            }
        }

        _logger.LogInformation("NamedPipeServer: stopped.");
    }

    /// <summary>Stops the server by cancelling its internal token.</summary>
    public void Stop() => _cts?.Cancel();

    // -------------------------------------------------------------------------
    // Connection handler
    // -------------------------------------------------------------------------

    private async Task HandleConnectionAsync(NamedPipeServerStream pipe, CancellationToken ct)
    {
        try
        {
            while (pipe.IsConnected && !ct.IsCancellationRequested)
            {
                // Read 4-byte LE length prefix.
                byte[] lenBuf = new byte[4];
                int read = await ReadExactAsync(pipe, lenBuf, 0, 4, ct).ConfigureAwait(false);
                if (read < 4) break; // client disconnected

                uint msgLen = BitConverter.ToUInt32(lenBuf, 0);

                // Enforce 64 KB maximum (Requirement 8.7).
                if (msgLen > MaxMsgSize)
                {
                    _logger.LogWarning(
                        "NamedPipeServer: oversize message ({Len} bytes) — closing connection.", msgLen);
                    break;
                }

                // Read JSON body.
                byte[] body = new byte[msgLen];
                read = await ReadExactAsync(pipe, body, 0, (int)msgLen, ct).ConfigureAwait(false);
                if (read < (int)msgLen) break;

                string json = Encoding.UTF8.GetString(body);

                // Extract the "type" field from the JSON to dispatch.
                string? messageType = null;
                try
                {
                    using var doc = JsonDocument.Parse(json);
                    if (doc.RootElement.TryGetProperty("type", out var typeProp))
                        messageType = typeProp.GetString();
                }
                catch (JsonException ex)
                {
                    _logger.LogWarning(ex, "NamedPipeServer: malformed JSON — closing connection.");
                    break;
                }

                if (messageType is null)
                {
                    _logger.LogWarning("NamedPipeServer: message missing 'type' field.");
                    continue;
                }

                // Dispatch to handler.
                object? response;
                try
                {
                    response = await _handler.HandleAsync(messageType, json, ct).ConfigureAwait(false);
                }
                catch (Exception ex)
                {
                    _logger.LogError(ex, "NamedPipeServer: handler threw for type '{Type}'.", messageType);
                    continue;
                }

                // Send response (if any).
                if (response is not null)
                {
                    byte[] responseJson = JsonSerializer.SerializeToUtf8Bytes(response);
                    byte[] responseLen  = BitConverter.GetBytes((uint)responseJson.Length);
                    await pipe.WriteAsync(responseLen, ct).ConfigureAwait(false);
                    await pipe.WriteAsync(responseJson, ct).ConfigureAwait(false);
                    await pipe.FlushAsync(ct).ConfigureAwait(false);
                }
            }
        }
        catch (OperationCanceledException) { /* expected on shutdown */ }
        catch (Exception ex)
        {
            _logger.LogError(ex, "NamedPipeServer: error handling connection.");
        }

        _logger.LogInformation("NamedPipeServer: client disconnected.");
    }

    // -------------------------------------------------------------------------
    // Helpers
    // -------------------------------------------------------------------------

    private static async Task<int> ReadExactAsync(
        Stream stream, byte[] buffer, int offset, int count, CancellationToken ct)
    {
        int total = 0;
        while (total < count)
        {
            int n = await stream.ReadAsync(buffer.AsMemory(offset + total, count - total), ct)
                                .ConfigureAwait(false);
            if (n == 0) break; // stream closed
            total += n;
        }
        return total;
    }
}
