// Feature: pc-unlock, Property 10
// Feature: pc-unlock, Property 11
// Feature: pc-unlock, Property 12
//
// ValidationRejectionPropertyTests — property-based tests for the three
// pre-signature rejection paths in SessionNonceManager.ValidateResponse.
//
// Property 10: Replay prevention — consumed nonce rejection
//   Validates: Requirements 5.4, 5.8, 13.1
//
// Property 11: Expired challenge rejection
//   Validates: Requirements 5.3, 5.8, 13.2
//
// Property 12: Session ID mismatch rejection
//   Validates: Requirements 13.3

using FsCheck;
using FsCheck.Fluent;
using FsCheck.Xunit;
using Microsoft.Extensions.Logging.Abstractions;
using PCUnlockService.Session;
using Xunit;

namespace PCUnlockService.Tests.Session;

// ---------------------------------------------------------------------------
// Shared file-scoped helpers
// ---------------------------------------------------------------------------

/// <summary>
/// Minimal in-memory stub for <see cref="IConsumedNonceStore"/>.
/// Backed by a <see cref="HashSet{T}"/> of Base64-encoded nonces.
/// </summary>
file sealed class StubNonceStore : IConsumedNonceStore
{
    private readonly HashSet<string> _consumed = new(StringComparer.Ordinal);

    /// <summary>Pre-seed a nonce so that <see cref="Contains"/> returns <c>true</c>.</summary>
    public void AddConsumed(byte[] nonce) => _consumed.Add(Convert.ToBase64String(nonce));

    public void Load() { }

    public bool Contains(byte[] nonce)
    {
        if (nonce is null || nonce.Length == 0) return false;
        return _consumed.Contains(Convert.ToBase64String(nonce));
    }

    public void Append(byte[] nonce) => AddConsumed(nonce);
}

/// <summary>Shared helpers used by all three property test classes in this file.</summary>
file static class Helpers
{
    /// <summary>
    /// Injects <paramref name="session"/> into the private <c>_activeSession</c>
    /// field of <paramref name="manager"/> using reflection, allowing tests to
    /// control session state without waiting or relying on clock drift.
    /// </summary>
    public static void SetActiveSession(SessionNonceManager manager, UnlockSession session)
    {
        var field = typeof(SessionNonceManager)
            .GetField("_activeSession",
                System.Reflection.BindingFlags.NonPublic |
                System.Reflection.BindingFlags.Instance)
            ?? throw new InvalidOperationException(
                "Reflection: could not locate '_activeSession' field on SessionNonceManager.");
        field.SetValue(manager, session);
    }

    /// <summary>Constructs a <see cref="BleResponse"/> carrying the given <paramref name="sessionId"/>.</summary>
    public static BleResponse MakeResponse(Guid sessionId) =>
        new()
        {
            Version      = 1,
            SessionId    = sessionId,
            DeviceId     = Guid.NewGuid(),
            SignatureDER = new byte[] { 0x30, 0x44 }, // minimal DER stub — not verified here
        };

    /// <summary>
    /// Creates an <see cref="UnlockSession"/> whose <c>ExpiresAt</c> is already in
    /// the past by the given number of seconds.
    /// </summary>
    public static UnlockSession MakeExpiredSession(string deviceId, int secondsElapsed = 10) =>
        new()
        {
            SessionId = Guid.NewGuid(),
            Nonce     = System.Security.Cryptography.RandomNumberGenerator.GetBytes(32),
            ExpiresAt = DateTimeOffset.UtcNow.ToUnixTimeSeconds() - secondsElapsed,
            DeviceId  = deviceId,
        };
}

// ===========================================================================
// Property 10 — Replay prevention: consumed nonce rejection
// ===========================================================================

/// <summary>
/// Property 10: For any nonce already present in <see cref="IConsumedNonceStore"/>,
/// <see cref="SessionNonceManager.ValidateResponse"/> MUST return
/// <see cref="ResponseRejectionReason.ReplayedNonce"/> before reaching signature
/// verification, and <see cref="ResponseValidationResult.IsValid"/> MUST be
/// <c>false</c>.
/// Validates: Requirements 5.4, 5.8, 13.1
/// </summary>
public sealed class ReplayPreventionPropertyTests
{
    // -----------------------------------------------------------------------
    // Property 10 — property-based (100 iterations)
    // -----------------------------------------------------------------------

    /// <summary>
    /// **Validates: Requirements 5.4, 5.8, 13.1**
    ///
    /// For any arbitrary 32-byte nonce pre-seeded into <see cref="StubNonceStore"/>,
    /// <see cref="SessionNonceManager.ValidateResponse"/> MUST reject the response
    /// with <see cref="ResponseRejectionReason.ReplayedNonce"/> and
    /// <c>IsValid == false</c> — without reaching signature verification.
    /// </summary>
    [Property(MaxTest = 100)]
    public Property ReplayedNonce_IsRejected_BeforeSignatureVerification()
    {
        // Feature: pc-unlock, Property 10
        return Prop.ForAll(
            Arb.Generate<byte>().ArrayOf(32).ToArbitrary(),
            nonce =>
            {
                // Arrange
                var store   = new StubNonceStore();
                var manager = new SessionNonceManager(store, NullLogger<SessionNonceManager>.Instance);

                // Start a fresh, non-expired session so expiry/mismatch checks pass.
                var session = manager.StartSession("device-replay-prop-10");

                // Replace the session's nonce with the generated one so the store
                // lookup matches, while keeping a valid sessionId and future expiresAt.
                var sessionWithGeneratedNonce = new UnlockSession
                {
                    SessionId = session.SessionId,
                    Nonce     = nonce,
                    ExpiresAt = DateTimeOffset.UtcNow.ToUnixTimeSeconds() + 60,
                    DeviceId  = session.DeviceId,
                };
                Helpers.SetActiveSession(manager, sessionWithGeneratedNonce);

                // Pre-seed the exact same nonce bytes into the store.
                store.AddConsumed(nonce);

                // Build a response that carries the correct sessionId (so session
                // mismatch is not triggered first) — only the nonce check fires.
                var response = Helpers.MakeResponse(sessionWithGeneratedNonce.SessionId);

                // Act
                var result = manager.ValidateResponse(response);

                // Assert
                return (!result.IsValid)
                    .Label($"IsValid must be false for a replayed nonce")
                    .And(result.Reason == ResponseRejectionReason.ReplayedNonce)
                    .Label($"Reason must be ReplayedNonce (was {result.Reason})");
            });
    }

    // -----------------------------------------------------------------------
    // Property 10 — concrete [Fact] example
    // -----------------------------------------------------------------------

    /// <summary>
    /// Concrete example: a known 32-byte nonce pre-seeded into the store causes
    /// <see cref="ResponseRejectionReason.ReplayedNonce"/> rejection.
    /// Validates: Requirements 5.4, 13.1
    /// </summary>
    [Fact]
    public void ReplayedNonce_ConcreteExample_IsRejected()
    {
        // Feature: pc-unlock, Property 10
        // Arrange
        var nonce   = new byte[32];
        new Random(42).NextBytes(nonce);

        var store   = new StubNonceStore();
        var manager = new SessionNonceManager(store, NullLogger<SessionNonceManager>.Instance);
        var session = manager.StartSession("device-replay-fact-10");

        var sessionWithNonce = new UnlockSession
        {
            SessionId = session.SessionId,
            Nonce     = nonce,
            ExpiresAt = DateTimeOffset.UtcNow.ToUnixTimeSeconds() + 60,
            DeviceId  = session.DeviceId,
        };
        Helpers.SetActiveSession(manager, sessionWithNonce);
        store.AddConsumed(nonce);

        var response = Helpers.MakeResponse(sessionWithNonce.SessionId);

        // Act
        var result = manager.ValidateResponse(response);

        // Assert
        Assert.False(result.IsValid);
        Assert.Equal(ResponseRejectionReason.ReplayedNonce, result.Reason);
    }
}

// ===========================================================================
// Property 11 — Expired challenge rejection
// ===========================================================================

/// <summary>
/// Property 11: For any session whose <c>ExpiresAt</c> is in the past,
/// <see cref="SessionNonceManager.ValidateResponse"/> MUST return
/// <see cref="ResponseRejectionReason.Expired"/> and
/// <see cref="ResponseValidationResult.IsValid"/> MUST be <c>false</c>.
/// Validates: Requirements 5.3, 5.8, 13.2
/// </summary>
public sealed class ExpiredChallengePropertyTests
{
    // -----------------------------------------------------------------------
    // Property 11 — property-based (100 iterations)
    // -----------------------------------------------------------------------

    /// <summary>
    /// **Validates: Requirements 5.3, 5.8, 13.2**
    ///
    /// For any elapsed duration between 1 and 3600 seconds, a session whose
    /// <c>ExpiresAt</c> is that many seconds in the past MUST be rejected with
    /// <see cref="ResponseRejectionReason.Expired"/> and <c>IsValid == false</c>.
    /// </summary>
    [Property(MaxTest = 100)]
    public Property ExpiredChallenge_IsRejected_BeforeSignatureVerification()
    {
        // Feature: pc-unlock, Property 11
        return Prop.ForAll(
            Gen.Choose(1, 3600).ToArbitrary(),
            elapsedSeconds =>
            {
                // Arrange
                var store   = new StubNonceStore();
                var manager = new SessionNonceManager(store, NullLogger<SessionNonceManager>.Instance);

                // Inject a session that expired `elapsedSeconds` ago.
                var expiredSession = Helpers.MakeExpiredSession("device-expired-prop-11", elapsedSeconds);
                Helpers.SetActiveSession(manager, expiredSession);

                // The sessionId in the response matches — only expiry check fires.
                var response = Helpers.MakeResponse(expiredSession.SessionId);

                // Act
                var result = manager.ValidateResponse(response);

                // Assert
                return (!result.IsValid)
                    .Label($"IsValid must be false for an expired session (elapsed={elapsedSeconds}s)")
                    .And(result.Reason == ResponseRejectionReason.Expired)
                    .Label($"Reason must be Expired (was {result.Reason}, elapsed={elapsedSeconds}s)");
            });
    }

    // -----------------------------------------------------------------------
    // Property 11 — concrete [Fact] example
    // -----------------------------------------------------------------------

    /// <summary>
    /// Concrete example: a session expired 30 seconds ago is rejected with
    /// <see cref="ResponseRejectionReason.Expired"/>.
    /// Validates: Requirements 5.3, 13.2
    /// </summary>
    [Fact]
    public void ExpiredChallenge_ConcreteExample_IsRejected()
    {
        // Feature: pc-unlock, Property 11
        // Arrange
        var store   = new StubNonceStore();
        var manager = new SessionNonceManager(store, NullLogger<SessionNonceManager>.Instance);

        var expiredSession = Helpers.MakeExpiredSession("device-expired-fact-11", secondsElapsed: 30);
        Helpers.SetActiveSession(manager, expiredSession);

        var response = Helpers.MakeResponse(expiredSession.SessionId);

        // Act
        var result = manager.ValidateResponse(response);

        // Assert
        Assert.False(result.IsValid);
        Assert.Equal(ResponseRejectionReason.Expired, result.Reason);
    }
}

// ===========================================================================
// Property 12 — Session ID mismatch rejection
// ===========================================================================

/// <summary>
/// Property 12: For any <see cref="BleResponse"/> whose <c>SessionId</c> does
/// not match the active session's <c>SessionId</c>,
/// <see cref="SessionNonceManager.ValidateResponse"/> MUST return
/// <see cref="ResponseRejectionReason.SessionMismatch"/> and
/// <see cref="ResponseValidationResult.IsValid"/> MUST be <c>false</c>.
/// Validates: Requirements 13.3
/// </summary>
public sealed class SessionIdMismatchPropertyTests
{
    // -----------------------------------------------------------------------
    // Property 12 — property-based (100 iterations)
    // -----------------------------------------------------------------------

    /// <summary>
    /// **Validates: Requirements 13.3**
    ///
    /// For any arbitrary GUID that differs from the active session's ID,
    /// <see cref="SessionNonceManager.ValidateResponse"/> MUST reject the
    /// response with <see cref="ResponseRejectionReason.SessionMismatch"/> and
    /// <c>IsValid == false</c>.
    /// </summary>
    [Property(MaxTest = 100)]
    public Property SessionIdMismatch_IsRejected()
    {
        // Feature: pc-unlock, Property 12
        return Prop.ForAll(
            Arb.Generate<Guid>().ToArbitrary(),
            wrongId =>
            {
                // Arrange
                var store   = new StubNonceStore();
                var manager = new SessionNonceManager(store, NullLogger<SessionNonceManager>.Instance);

                // Start a valid, non-expired session.
                var session = manager.StartSession("device-mismatch-prop-12");

                // Filter out the (astronomically rare) case where the generated
                // GUID happens to equal the active session's ID — that would not
                // be a mismatch and is not the scenario under test.
                if (wrongId == session.SessionId)
                    return true.Label("skipped: generated GUID matched active sessionId (collision)");

                // Build a response carrying the wrong session ID.
                var response = Helpers.MakeResponse(wrongId);

                // Act
                var result = manager.ValidateResponse(response);

                // Assert
                return (!result.IsValid)
                    .Label($"IsValid must be false for mismatched sessionId")
                    .And(result.Reason == ResponseRejectionReason.SessionMismatch)
                    .Label($"Reason must be SessionMismatch (was {result.Reason})");
            });
    }

    // -----------------------------------------------------------------------
    // Property 12 — concrete [Fact] example
    // -----------------------------------------------------------------------

    /// <summary>
    /// Concrete example: a response carrying a deterministic wrong GUID is
    /// rejected with <see cref="ResponseRejectionReason.SessionMismatch"/>.
    /// Validates: Requirements 13.3
    /// </summary>
    [Fact]
    public void SessionIdMismatch_ConcreteExample_IsRejected()
    {
        // Feature: pc-unlock, Property 12
        // Arrange
        var store   = new StubNonceStore();
        var manager = new SessionNonceManager(store, NullLogger<SessionNonceManager>.Instance);
        var session = manager.StartSession("device-mismatch-fact-12");

        // A GUID that is guaranteed not to match the active session.
        var wrongId  = Guid.Parse("00000000-0000-0000-0000-000000000001");
        Assert.NotEqual(session.SessionId, wrongId); // self-check — extremely unlikely to collide

        var response = Helpers.MakeResponse(wrongId);

        // Act
        var result = manager.ValidateResponse(response);

        // Assert
        Assert.False(result.IsValid);
        Assert.Equal(ResponseRejectionReason.SessionMismatch, result.Reason);
    }
}
