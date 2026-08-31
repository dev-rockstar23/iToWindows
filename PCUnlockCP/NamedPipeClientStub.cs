// Feature: pc-unlock
// NamedPipeClient — CP side of the Named Pipe IPC channel to PCUnlockService.
//
// Sends UnlockRequest / ListDevicesRequest / RemoveDeviceRequest messages and
// awaits the matching response with a timeout that covers the 15-second BLE
// window plus a processing budget (Requirement 4.6).
//
// Message framing (matching the service's Named Pipe Server):
//   4-byte LE uint32 length prefix + UTF-8 JSON body.
//
// Requirements: 7.3, 7.5, 4.6

using System.IO.Pipes;
using System.Text;
using System.Text.Json;

namespace PCUnlockCP;

/// <summary>
/// Manages the Credential Provider's connection to
/// <c>\\.\pipe\PCUnlockService</c> and provides typed request/response helpers.
///
/// <para>
/// Each public method opens a fresh pipe connection, performs its exchange,
/// and closes the pipe.  This keeps the CP side stateless and avoids holding
/// a persistent connection that could interfere with service restarts.
/// </para>
/// </summary>
public sealed class NamedPipeClientStub : IDisposable
{
    private const string PipeName = "PCUnlockService";

    /// <summary>
    /// Total wait budget for an unlock round-trip:
    /// 15 s (BLE scan/connect, Requirement 4.6) + 5 s processing buffer.
    /// </summary>
    private static readonly TimeSpan UnlockTimeout   = TimeSpan.FromSeconds(20);

    /// <summary>Shorter timeout for non-BLE management operations.</summary>
    private static readonly TimeSpan ManagementTimeout = TimeSpan.FromSeconds(5);

    private NamedPipeClientStream? _pipe;

    // -----------------------------------------------------------------------
    // Connection
    // -----------------------------------------------------------------------

    /// <summary>
    /// Attempts a non-blocking connection to the Named Pipe.
    /// Returns <c>false</c> if the service is unavailable — callers should
    /// treat this as <see cref="TileHideReason.ServiceUnavailable"/>.
    /// </summary>
    public bool Connect()
    {
        try
        {
            _pipe = new NamedPipeClientStream(
                ".", PipeName, PipeDirection.InOut, PipeOptions.Asynchronous);
            _pipe.Connect(500); // quick availability check (500 ms)
            return true;
        }
        catch
        {
            _pipe?.Dispose();
            _pipe = null;
            return false;
        }
    }

    // -----------------------------------------------------------------------
    // Unlock request (tile selected by user)
    // -----------------------------------------------------------------------

    /// <summary>
    /// Sends an <c>UnlockRequest</c> and awaits the <c>UnlockResponse</c>.
    /// </summary>
    /// <param name="userId">The Windows user SID or name for logging.</param>
    /// <param name="ct">Optional external cancellation token.</param>
    /// <returns>
    /// <c>"success"</c>, <c>"failure"</c>, or <c>"timeout"</c>.
    /// </returns>
    public async Task<string> RequestUnlockAsync(
        string userId, CancellationToken ct = default)
    {
        if (_pipe is null || !_pipe.IsConnected)
            return "failure";

        try
        {
            await SendJsonAsync(new { type = "unlock_request", userId }, ct);

            using var cts = CancellationTokenSource.CreateLinkedTokenSource(ct);
            cts.CancelAfter(UnlockTimeout);

            var response = await ReceiveJsonAsync(cts.Token);
            if (response is null) return "failure";

            using var doc = JsonDocument.Parse(response);
            return doc.RootElement.TryGetProperty("result", out var r)
                ? r.GetString() ?? "failure"
                : "failure";
        }
        catch (OperationCanceledException)
        {
            return "timeout";
        }
        catch
        {
            return "failure";
        }
    }

    // -----------------------------------------------------------------------
    // Service status probe (tile visibility check)
    // -----------------------------------------------------------------------

    /// <summary>
    /// Queries the service for the current status (paired device count, BLE
    /// availability) to populate a <see cref="TileState"/>.
    /// Returns <see cref="TileState.Default"/> when the service is unreachable.
    /// </summary>
    public async Task<TileState> QueryStatusAsync(CancellationToken ct = default)
    {
        if (_pipe is null || !_pipe.IsConnected)
            return TileState.Default;

        try
        {
            await SendJsonAsync(new { type = "status_request" }, ct);

            using var cts = CancellationTokenSource.CreateLinkedTokenSource(ct);
            cts.CancelAfter(ManagementTimeout);

            var response = await ReceiveJsonAsync(cts.Token);
            if (response is null) return TileState.Default;

            using var doc = JsonDocument.Parse(response);
            var root = doc.RootElement;

            int  paired = root.TryGetProperty("pairedDeviceCount", out var pd)
                ? pd.GetInt32() : 0;
            bool ble    = !root.TryGetProperty("bleAvailable", out var bl)
                || bl.GetBoolean();

            return new TileState(
                ServiceAvailable:  true,
                PairedDeviceCount: paired,
                BleAvailable:      ble);
        }
        catch
        {
            return TileState.Default;
        }
    }

    // -----------------------------------------------------------------------
    // Framing helpers
    // -----------------------------------------------------------------------

    private async Task SendJsonAsync(object payload, CancellationToken ct)
    {
        ArgumentNullException.ThrowIfNull(_pipe);

        byte[] body   = Encoding.UTF8.GetBytes(JsonSerializer.Serialize(payload));
        byte[] prefix = BitConverter.GetBytes((uint)body.Length);

        await _pipe.WriteAsync(prefix, ct);
        await _pipe.WriteAsync(body,   ct);
        await _pipe.FlushAsync(ct);
    }

    private async Task<byte[]?> ReceiveJsonAsync(CancellationToken ct)
    {
        ArgumentNullException.ThrowIfNull(_pipe);

        byte[] lenBuf = new byte[4];
        await ReadExactAsync(_pipe, lenBuf, 4, ct);
        uint len = BitConverter.ToUInt32(lenBuf, 0);

        // Guard against runaway / malformed messages (max 64 KB per spec).
        if (len == 0 || len > 65_536) return null;

        byte[] body = new byte[len];
        await ReadExactAsync(_pipe, body, (int)len, ct);
        return body;
    }

    private static async Task ReadExactAsync(
        Stream stream, byte[] buf, int count, CancellationToken ct)
    {
        int total = 0;
        while (total < count)
        {
            int n = await stream.ReadAsync(
                buf.AsMemory(total, count - total), ct);
            if (n == 0) throw new EndOfStreamException("Pipe closed unexpectedly.");
            total += n;
        }
    }

    // -----------------------------------------------------------------------
    // IDisposable
    // -----------------------------------------------------------------------

    public void Dispose() => _pipe?.Dispose();
}
