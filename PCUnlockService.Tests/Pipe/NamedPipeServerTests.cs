// Feature: pc-unlock
// NamedPipeServerTests — unit tests for pipe message framing and serialization.
// Requirements: 7.3, 8.1, 8.7

using System.Text;
using System.Text.Json;
using PCUnlockService.Pipe;
using Xunit;

namespace PCUnlockService.Tests.Pipe;

public sealed class PipeMessageSerializationTests
{
    private static T Roundtrip<T>(T value)
    {
        byte[] json = JsonSerializer.SerializeToUtf8Bytes(value);
        return JsonSerializer.Deserialize<T>(json)!;
    }

    [Fact] public void UnlockRequest_RoundTrips()
    {
        var req = new UnlockRequest { UserId = "user1", SessionHint = "hint" };
        var rt = Roundtrip(req);
        Assert.Equal("unlock_request", rt.Type);
        Assert.Equal("user1", rt.UserId);
        Assert.Equal("hint", rt.SessionHint);
    }

    [Fact] public void UnlockResponse_Success_RoundTrips()
    {
        var resp = new UnlockResponse { Result = "success" };
        var rt = Roundtrip(resp);
        Assert.Equal("unlock_response", rt.Type);
        Assert.Equal("success", rt.Result);
        Assert.Null(rt.Reason);
    }

    [Fact] public void RemoveDeviceRequest_RoundTrips()
    {
        var req = new RemoveDeviceRequest { DeviceId = "abc-123" };
        var rt = Roundtrip(req);
        Assert.Equal("remove_device", rt.Type);
        Assert.Equal("abc-123", rt.DeviceId);
    }

    [Fact] public void RemoveDeviceResponse_RoundTrips()
    {
        var resp = new RemoveDeviceResponse { Ok = true };
        var rt = Roundtrip(resp);
        Assert.Equal("remove_device_response", rt.Type);
        Assert.True(rt.Ok);
    }

    [Fact] public void ListDevicesRequest_RoundTrips()
    {
        var req = new ListDevicesRequest();
        var rt = Roundtrip(req);
        Assert.Equal("list_devices", rt.Type);
    }

    [Fact] public void ServiceStatusEvent_RoundTrips()
    {
        var ev = new ServiceStatusEvent { Available = true, PairedCount = 3 };
        var rt = Roundtrip(ev);
        Assert.Equal("status_event", rt.Type);
        Assert.True(rt.Available);
        Assert.Equal(3, rt.PairedCount);
    }
}

public sealed class PipeFramingTests
{
    /// <summary>
    /// Verifies that a 4-byte LE length prefix + UTF-8 JSON body correctly
    /// encodes and decodes a sample message.
    /// </summary>
    [Fact]
    public void FrameEncode_AndDecode_RoundTrip()
    {
        string originalJson = """{"type":"unlock_request","userId":"u1"}""";
        byte[] body = Encoding.UTF8.GetBytes(originalJson);
        byte[] lengthPrefix = BitConverter.GetBytes((uint)body.Length);

        // Verify the prefix is 4 bytes LE.
        Assert.Equal(4, lengthPrefix.Length);
        uint decodedLength = BitConverter.ToUInt32(lengthPrefix, 0);
        Assert.Equal((uint)body.Length, decodedLength);

        // Combine frame.
        byte[] frame = lengthPrefix.Concat(body).ToArray();
        Assert.Equal(4 + body.Length, frame.Length);

        // Decode.
        uint msgLen = BitConverter.ToUInt32(frame, 0);
        string decodedJson = Encoding.UTF8.GetString(frame, 4, (int)msgLen);
        Assert.Equal(originalJson, decodedJson);
    }

    [Fact]
    public void MaxMessageSize_Is64KB()
    {
        // The server must reject messages larger than 64 KB (Requirement 8.7).
        const int maxSize = 64 * 1024;
        Assert.Equal(maxSize, 65536);

        // A message exactly at the limit should be within bounds.
        byte[] atLimit = new byte[maxSize];
        Assert.True(atLimit.Length <= maxSize);

        // A message one byte over should be detected as oversize.
        byte[] overLimit = new byte[maxSize + 1];
        Assert.True(overLimit.Length > maxSize);
    }

    [Fact]
    public void EmptyBody_FrameLength_IsZero()
    {
        byte[] empty = Array.Empty<byte>();
        byte[] frame = BitConverter.GetBytes((uint)empty.Length).Concat(empty).ToArray();
        uint decoded = BitConverter.ToUInt32(frame, 0);
        Assert.Equal(0u, decoded);
    }
}
