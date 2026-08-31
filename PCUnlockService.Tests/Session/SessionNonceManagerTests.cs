// Feature: pc-unlock
// SessionNonceManagerTests — unit tests for SessionNonceManager.ValidateResponse.
// Requirements: 5.3, 5.4, 5.8, 13.1, 13.2, 13.3

using Microsoft.Extensions.Logging.Abstractions;
using PCUnlockService.Session;
using Xunit;

namespace PCUnlockService.Tests.Session;

// ---------------------------------------------------------------------------
// Stub: IConsumedNonceStore
// ---------------------------------------------------------------------------

/// <summary>
/// Minimal in-memory stub for <see cref="IConsumedNonceStore"/> used in unit tests.
/// The <see cref="Contains"/> method returns a value controlled by the test.
/// </summary>
file sealed class StubNonceStore : IConsumedNonceStore
{
    private readonly HashSet<string> _consumed = new(StringComparer.Ordinal);

    /// <summary>Pre-seed the store with a nonce so <see cref="Contains"/> returns true.</summary>
    public void AddConsumed(byte[] nonce) => _consumed.Add(Convert.ToBase64String(nonce));

    public void Load() { }

    public bool Contains(byte[] nonce)
    {
        if (nonce is null || nonce.Length == 0) return false;
        return _consumed.Contains(Convert.ToBase64String(nonce));
    }

    public void Append(byte[] nonce) => AddConsumed(nonce);
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

public sealed class SessionNonceManagerTests
{
    // Convenience factory — uses NullLogger and the provided stub store.
    private static SessionNonceManager Make(StubNonceStore store) =>
        new(store, NullLogger<SessionNonceManager>.Instance);

    // Build a BleResponse that echoes the session's sessionId by default.
    private static BleResponse ResponseFor(UnlockSession session, Guid? overrideSessionId = null) =>
        new()
        {
            Version      = 1,
            SessionId    = overrideSessionId ?? session.SessionId,
            DeviceId     = Guid.NewGuid(),
            SignatureDER = new byte[] { 0x30, 0x44 }, // minimal DER stub
        };

    // -----------------------------------------------------------------------
    // 1. No active session
    // -----------------------------------------------------------------------

    [Fact]
    public void ValidateResponse_NoActiveSession_ReturnsNoActiveSession()
    {
        // Arrange — manager with no session started
        var store   = new StubNonceStore();
        var manager = Make(store);
        var response = new BleResponse
        {
            Version      = 1,
            SessionId    = Guid.NewGuid(),
            DeviceId     = Guid.NewGuid(),
            SignatureDER = Array.Empty<byte>(),
        };

        // Act
        var result = manager.ValidateResponse(response);

        // Assert
        Assert.False(result.IsValid);
        Assert.Equal(ResponseRejectionReason.NoActiveSession, result.Reason);
    }

    // -----------------------------------------------------------------------
    // 2. Expired session (Requirement 5.3, 13.2)
    // -----------------------------------------------------------------------

    [Fact]
    public void ValidateResponse_ExpiredSession_ReturnsExpired()
    {
        // Arrange — start a session, then manually expire it by injecting an
        // already-elapsed expiresAt via reflection on the backing field.
        var store   = new StubNonceStore();
        var manager = Make(store);

        // Start a real session so _activeSession is populated.
        var session = manager.StartSession("device-expired-test");

        // Replace _activeSession with an expired copy via the private field.
        // We use the record copy-constructor pattern via reflection to avoid
        // coupling to internal details of UnlockSession too much.
        var expiredSession = new UnlockSession
        {
            SessionId = session.SessionId,
            Nonce     = session.Nonce,
            ExpiresAt = DateTimeOffset.UtcNow.ToUnixTimeSeconds() - 1, // already in the past
            DeviceId  = session.DeviceId,
        };
        SetActiveSession(manager, expiredSession);

        var response = ResponseFor(expiredSession);

        // Act
        var result = manager.ValidateResponse(response);

        // Assert
        Assert.False(result.IsValid);
        Assert.Equal(ResponseRejectionReason.Expired, result.Reason);
    }

    // -----------------------------------------------------------------------
    // 3. Session ID mismatch (Requirement 13.3)
    // -----------------------------------------------------------------------

    [Fact]
    public void ValidateResponse_SessionIdMismatch_ReturnsSessionMismatch()
    {
        // Arrange
        var store   = new StubNonceStore();
        var manager = Make(store);
        manager.StartSession("device-mismatch-test");

        // Response carries a different sessionId
        var mismatchedResponse = new BleResponse
        {
            Version      = 1,
            SessionId    = Guid.NewGuid(), // does not match active session
            DeviceId     = Guid.NewGuid(),
            SignatureDER = Array.Empty<byte>(),
        };

        // Act
        var result = manager.ValidateResponse(mismatchedResponse);

        // Assert
        Assert.False(result.IsValid);
        Assert.Equal(ResponseRejectionReason.SessionMismatch, result.Reason);
    }

    // -----------------------------------------------------------------------
    // 4. Replayed nonce (Requirement 5.4, 13.1)
    // -----------------------------------------------------------------------

    [Fact]
    public void ValidateResponse_ReplayedNonce_ReturnsReplayedNonce()
    {
        // Arrange — start a session, then pre-seed its nonce into the store.
        var store   = new StubNonceStore();
        var manager = Make(store);
        var session = manager.StartSession("device-replay-test");

        // Mark the session nonce as already consumed.
        store.AddConsumed(session.Nonce);

        var response = ResponseFor(session);

        // Act
        var result = manager.ValidateResponse(response);

        // Assert
        Assert.False(result.IsValid);
        Assert.Equal(ResponseRejectionReason.ReplayedNonce, result.Reason);
    }

    // -----------------------------------------------------------------------
    // 5. All checks pass → Valid (Requirements 5.3, 5.4, 13.1, 13.2, 13.3)
    // -----------------------------------------------------------------------

    [Fact]
    public void ValidateResponse_AllChecksPass_ReturnsValid()
    {
        // Arrange — fresh session, nonce not in store, response echoes correct sessionId.
        var store   = new StubNonceStore();
        var manager = Make(store);
        var session = manager.StartSession("device-valid-test");

        // Nonce is NOT pre-seeded — store.Contains returns false.
        var response = ResponseFor(session);

        // Act
        var result = manager.ValidateResponse(response);

        // Assert
        Assert.True(result.IsValid);
        Assert.Equal(ResponseRejectionReason.None, result.Reason);
    }

    // -----------------------------------------------------------------------
    // Helpers
    // -----------------------------------------------------------------------

    /// <summary>
    /// Uses reflection to inject <paramref name="session"/> into the private
    /// <c>_activeSession</c> field of <paramref name="manager"/> so that
    /// tests can control expiry without waiting.
    /// </summary>
    private static void SetActiveSession(SessionNonceManager manager, UnlockSession session)
    {
        var field = typeof(SessionNonceManager)
            .GetField("_activeSession",
                System.Reflection.BindingFlags.NonPublic |
                System.Reflection.BindingFlags.Instance)
            ?? throw new InvalidOperationException(
                "Reflection: could not find '_activeSession' field on SessionNonceManager.");
        field.SetValue(manager, session);
    }
}
