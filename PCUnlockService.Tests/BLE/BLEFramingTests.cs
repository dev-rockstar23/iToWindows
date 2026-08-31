// Feature: pc-unlock
// BLEFramingTests — unit tests verifying BLESessionResult factory methods and
// BLECentral protocol constants.
// Validates: Requirements 4.1, 4.3, 4.6

using PCUnlockService.BLE;
using Xunit;

namespace PCUnlockService.Tests.BLE;

/// <summary>
/// Unit tests for <see cref="BLESessionResult"/> factory methods and
/// <see cref="BLECentral"/> protocol constants.
/// These tests do not require BLE hardware and run on any machine.
/// </summary>
public sealed class BLEFramingTests
{
    // -----------------------------------------------------------------------
    // Protocol constants
    // -----------------------------------------------------------------------

    /// <summary>
    /// Challenge payload must be exactly 57 bytes:
    /// version[1] + sessionId[16] + nonce[32] + expiresAt[8].
    /// (Requirement 5.2)
    /// </summary>
    [Fact]
    public void BLECentral_ChallengeByteLength_Is57()
    {
        Assert.Equal(57, BLECentral.ChallengeByteLength);
    }

    /// <summary>
    /// Session timeout must be exactly 15 seconds (Requirement 4.6).
    /// </summary>
    [Fact]
    public void BLECentral_SessionTimeout_IsExactly15Seconds()
    {
        Assert.Equal(TimeSpan.FromSeconds(15), BLECentral.SessionTimeout);
    }

    // -----------------------------------------------------------------------
    // BLESessionResult.Succeeded
    // -----------------------------------------------------------------------

    [Fact]
    public void Succeeded_Status_IsSuccess()
    {
        var result = BLESessionResult.Succeeded(new byte[32], new byte[16]);
        Assert.Equal(BLESessionStatus.Success, result.Status);
    }

    [Fact]
    public void Succeeded_ResponseBytes_IsNonNull()
    {
        var bytes = new byte[] { 0x01, 0x02 };
        var result = BLESessionResult.Succeeded(bytes, new byte[16]);
        Assert.NotNull(result.ResponseBytes);
        Assert.Equal(bytes, result.ResponseBytes);
    }

    [Fact]
    public void Succeeded_DeviceId_IsNonNull()
    {
        var deviceId = new byte[16];
        var result = BLESessionResult.Succeeded(new byte[32], deviceId);
        Assert.NotNull(result.DeviceId);
        Assert.Equal(deviceId, result.DeviceId);
    }

    [Fact]
    public void Succeeded_ErrorMessage_IsNull()
    {
        var result = BLESessionResult.Succeeded(new byte[32], new byte[16]);
        Assert.Null(result.ErrorMessage);
    }

    // -----------------------------------------------------------------------
    // BLESessionResult.TimedOut
    // -----------------------------------------------------------------------

    [Fact]
    public void TimedOut_Status_IsTimeout()
    {
        var result = BLESessionResult.TimedOut();
        Assert.Equal(BLESessionStatus.Timeout, result.Status);
    }

    [Fact]
    public void TimedOut_ResponseBytes_IsNull()
    {
        var result = BLESessionResult.TimedOut();
        Assert.Null(result.ResponseBytes);
    }

    [Fact]
    public void TimedOut_DeviceId_IsNull()
    {
        var result = BLESessionResult.TimedOut();
        Assert.Null(result.DeviceId);
    }

    [Fact]
    public void TimedOut_ErrorMessage_IsNonNull()
    {
        // The timeout message must be informative (non-empty).
        var result = BLESessionResult.TimedOut();
        Assert.NotNull(result.ErrorMessage);
        Assert.NotEmpty(result.ErrorMessage);
    }

    // -----------------------------------------------------------------------
    // BLESessionResult.Failed
    // -----------------------------------------------------------------------

    [Fact]
    public void Failed_Status_IsError()
    {
        var result = BLESessionResult.Failed("something went wrong");
        Assert.Equal(BLESessionStatus.Error, result.Status);
    }

    [Fact]
    public void Failed_ResponseBytes_IsNull()
    {
        var result = BLESessionResult.Failed("err");
        Assert.Null(result.ResponseBytes);
    }

    [Fact]
    public void Failed_ErrorMessage_MatchesInput()
    {
        const string msg = "GATT service not found";
        var result = BLESessionResult.Failed(msg);
        Assert.Equal(msg, result.ErrorMessage);
    }

    // -----------------------------------------------------------------------
    // BLESessionResult.DeviceNotRecognised
    // -----------------------------------------------------------------------

    [Fact]
    public void DeviceNotRecognised_Status_IsUnknownDevice()
    {
        var result = BLESessionResult.DeviceNotRecognised(new byte[16]);
        Assert.Equal(BLESessionStatus.UnknownDevice, result.Status);
    }

    [Fact]
    public void DeviceNotRecognised_ResponseBytes_IsNull()
    {
        var result = BLESessionResult.DeviceNotRecognised(new byte[16]);
        Assert.Null(result.ResponseBytes);
    }

    [Fact]
    public void DeviceNotRecognised_DeviceId_IsNonNull()
    {
        var id = new byte[16];
        var result = BLESessionResult.DeviceNotRecognised(id);
        Assert.NotNull(result.DeviceId);
        Assert.Equal(id, result.DeviceId);
    }
}
