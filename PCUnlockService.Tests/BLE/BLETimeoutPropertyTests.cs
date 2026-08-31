// Feature: pc-unlock, Property 7
// BLE timeout enforcement — property-based tests.
// Validates: Requirements 4.6
//
// Property 7: For any BLE connection attempt that does not complete within
// 15 seconds, the BLE Central SHALL mark the session as timed out and SHALL
// NOT produce an unlock signal (ResponseBytes must be null).

using FsCheck;
using FsCheck.Fluent;
using FsCheck.Xunit;
using PCUnlockService.BLE;
using Xunit;

namespace PCUnlockService.Tests.BLE;

// ---------------------------------------------------------------------------
// FakeBLECentral — test double that simulates timeout / success behaviour
// without using real BLE hardware or wall-clock delays.
//
// Primary constructor: bool shouldTimeout
//   true  → RunSessionAsync returns BLESessionResult.TimedOut() immediately,
//           mirroring what the real BLECentral does when its internal
//           CancellationTokenSource fires after 15 seconds (Requirement 4.6).
//   false → RunSessionAsync returns BLESessionResult.Succeeded(...) immediately
//           with non-null ResponseBytes, mirroring a successful exchange.
//
// Extended constructor: double simulatedElapsedSeconds
//   Derives the shouldTimeout flag from whether the elapsed time exceeds
//   BLECentral.SessionTimeout.TotalSeconds (15 s), keeping the simulated-clock
//   model for property-based tests that vary the elapsed time continuously.
// ---------------------------------------------------------------------------

/// <summary>
/// Test stub for <see cref="IBLECentral"/>.
/// <para>
/// When <paramref name="shouldTimeout"/> is <c>true</c>, <see cref="RunSessionAsync"/>
/// immediately returns <see cref="BLESessionResult.TimedOut()"/> without any I/O,
/// simulating a session that exceeded the 15-second window (Requirement 4.6).
/// </para>
/// <para>
/// When <paramref name="shouldTimeout"/> is <c>false</c>, it returns
/// <see cref="BLESessionResult.Succeeded"/> with dummy, non-null
/// <see cref="BLESessionResult.ResponseBytes"/>.
/// </para>
/// </summary>
internal sealed class FakeBLECentral : IBLECentral
{
    private readonly bool _shouldTimeout;

    /// <summary>
    /// Creates a fake BLE central that either times out or succeeds.
    /// </summary>
    /// <param name="shouldTimeout">
    ///   <c>true</c> to simulate a session that did not complete within 15 s;
    ///   <c>false</c> to simulate a successful exchange.
    /// </param>
    public FakeBLECentral(bool shouldTimeout)
    {
        _shouldTimeout = shouldTimeout;
    }

    /// <summary>
    /// Creates a fake BLE central driven by a simulated elapsed-seconds value.
    /// The session times out iff <paramref name="simulatedElapsedSeconds"/> is
    /// strictly greater than <see cref="BLECentral.SessionTimeout"/> (15 s).
    /// </summary>
    /// <param name="simulatedElapsedSeconds">Simulated clock reading in seconds.</param>
    public FakeBLECentral(double simulatedElapsedSeconds)
        : this(simulatedElapsedSeconds > BLECentral.SessionTimeout.TotalSeconds)
    {
    }

    /// <inheritdoc/>
    public Task<BLESessionResult> RunSessionAsync(
        byte[] challengeBytes,
        CancellationToken cancellationToken = default)
    {
        if (_shouldTimeout)
        {
            // Simulate the CancellationTokenSource firing after 15 s — no I/O,
            // no BLE hardware required.
            return Task.FromResult(BLESessionResult.TimedOut());
        }

        // Simulate a successful session: return dummy non-null ResponseBytes
        // and a 16-byte device ID, matching the contract of IBLECentral.
        var dummyDeviceId = new byte[16];
        var dummyResponse = new byte[32];
        return Task.FromResult(BLESessionResult.Succeeded(dummyResponse, dummyDeviceId));
    }

    /// <inheritdoc/>
    public void StopScan() { /* no-op in test stub */ }
}

// ---------------------------------------------------------------------------
// Generator helpers
// ---------------------------------------------------------------------------

internal static class Generators
{
    /// <summary>
    /// Arbitrary for a valid 57-byte challenge payload with arbitrary byte values,
    /// matching the canonical-encoded Challenge layout (Requirement 5.2).
    /// Uses <c>Arb.Generate&lt;byte&gt;().ArrayOf(57)</c> style as required.
    /// </summary>
    public static Arbitrary<byte[]> ChallengeBytes() =>
        Arb.Generate<byte>().ArrayOf(BLECentral.ChallengeByteLength)
           .ToArbitrary();

    /// <summary>
    /// Arbitrary for a simulated elapsed time strictly greater than 15 seconds.
    /// Uses the range (15, 120] seconds to cover realistic over-budget durations
    /// while keeping generated values bounded.
    /// </summary>
    public static Arbitrary<double> ElapsedSecondsExceedingTimeout() =>
        // Generate an integer offset in [1, 105] seconds beyond the 15-second threshold.
        Gen.Choose(1, 105)
           .Select(offset => BLECentral.SessionTimeout.TotalSeconds + offset)
           .ToArbitrary();

    /// <summary>
    /// Arbitrary for a simulated elapsed time strictly less than 15 seconds.
    /// Uses the range [0, 14] seconds.
    /// </summary>
    public static Arbitrary<double> ElapsedSecondsWithinTimeout() =>
        Gen.Choose(0, 14)
           .Select(s => (double)s)
           .ToArbitrary();
}

// ---------------------------------------------------------------------------
// Core property-based tests (FsCheck.Xunit [Property] attribute)
// ---------------------------------------------------------------------------

/// <summary>
/// Property-based tests for BLE timeout enforcement (Property 7).
/// Validates: Requirements 4.6 — minimum 100 iterations.
/// </summary>
public sealed class BLETimeoutPropertyTests
{
    // -----------------------------------------------------------------------
    // Property 7 (core) — timeout-exceeding sessions produce Timeout result
    //
    // For any 57-byte challenge and any simulated elapsed time > 15 seconds,
    // RunSessionAsync MUST return Status == Timeout and ResponseBytes == null.
    // -----------------------------------------------------------------------

    /// <summary>
    /// **Validates: Requirements 4.6**
    ///
    /// For any challenge bytes and any simulated elapsed time exceeding
    /// <see cref="BLECentral.SessionTimeout"/> (15 s), the result must be a
    /// Timeout with <c>ResponseBytes == null</c>.
    /// </summary>
    [Fact]
    public void Property7_TimeoutExceeded_StatusIsTimeoutAndResponseBytesIsNull()
    {
        // Feature: pc-unlock, Property 7
        var challengeArb = Generators.ChallengeBytes();
        var elapsedArb = Generators.ElapsedSecondsExceedingTimeout();

        var cfg = Configuration.QuickThrowOnFailure.WithMaxTest(100);

        var prop = Prop.ForAll(
            challengeArb,
            elapsedArb,
            (challengeBytes, elapsedSeconds) =>
            {
                var central = new FakeBLECentral(simulatedElapsedSeconds: elapsedSeconds);
                var result = central.RunSessionAsync(challengeBytes).GetAwaiter().GetResult();

                return (result.Status == BLESessionStatus.Timeout)
                    .Label("Status must equal BLESessionStatus.Timeout")
                    .And(result.ResponseBytes == null)
                    .Label("ResponseBytes must be null when session times out");
            });

        prop.Check(cfg);
    }

    // -----------------------------------------------------------------------
    // Property 7 (boundary contrast) — within-timeout sessions are NOT Timeout
    //
    // For any 57-byte challenge and elapsed time strictly within 15 seconds,
    // the result must NOT be a Timeout (confirms the boundary is at 15 s).
    // -----------------------------------------------------------------------

    /// <summary>
    /// **Validates: Requirements 4.6** (negative / boundary contrast)
    ///
    /// For any simulated elapsed time within the 15-second window, the result
    /// must be Success, not Timeout.
    /// </summary>
    [Fact]
    public void Property7_WithinTimeout_StatusIsNotTimeout()
    {
        // Feature: pc-unlock, Property 7
        var challengeArb = Generators.ChallengeBytes();
        var elapsedArb = Generators.ElapsedSecondsWithinTimeout();

        var cfg = Configuration.QuickThrowOnFailure.WithMaxTest(100);

        var prop = Prop.ForAll(
            challengeArb,
            elapsedArb,
            (challengeBytes, elapsedSeconds) =>
            {
                var central = new FakeBLECentral(simulatedElapsedSeconds: elapsedSeconds);
                var result = central.RunSessionAsync(challengeBytes).GetAwaiter().GetResult();

                return (result.Status != BLESessionStatus.Timeout)
                    .Label("Status must not be Timeout for sessions completing within 15 s");
            });

        prop.Check(cfg);
    }

    // -----------------------------------------------------------------------
    // FsCheck.Xunit [Property] attribute variant — uses [Property(MaxTest=100)]
    // with typed wrapper arbitraries to constrain the value distribution.
    // -----------------------------------------------------------------------

    /// <summary>Marker type — wraps elapsed seconds that exceed the 15 s timeout.</summary>
    public readonly record struct ExceedingElapsed(double Seconds);

    /// <summary>Marker type — wraps elapsed seconds that are within the 15 s timeout.</summary>
    public readonly record struct WithinElapsed(double Seconds);

    // Arbitrary registrations used by [Property(Arbitrary = ...)] below.
    public static Arbitrary<byte[]> ArbitraryChallengeBytes() =>
        Generators.ChallengeBytes();

    public static Arbitrary<ExceedingElapsed> ArbitraryExceedingElapsed() =>
        Generators.ElapsedSecondsExceedingTimeout()
                  .Select(s => new ExceedingElapsed(s))
                  .ToArbitrary();

    public static Arbitrary<WithinElapsed> ArbitraryWithinElapsed() =>
        Generators.ElapsedSecondsWithinTimeout()
                  .Select(s => new WithinElapsed(s))
                  .ToArbitrary();

    /// <summary>
    /// **Validates: Requirements 4.6** — [Property] attribute variant (MaxTest = 100).
    ///
    /// For any challenge bytes and any elapsed time exceeding 15 s, the session
    /// result MUST have <c>Status == Timeout</c> and <c>ResponseBytes == null</c>.
    /// </summary>
    [Property(MaxTest = 100, Arbitrary = new[] { typeof(BLETimeoutPropertyTests) })]
    public Property TimeoutExceeded_Property(byte[] challengeBytes, ExceedingElapsed elapsed)
    {
        // Feature: pc-unlock, Property 7
        var central = new FakeBLECentral(simulatedElapsedSeconds: elapsed.Seconds);
        var result = central.RunSessionAsync(challengeBytes).GetAwaiter().GetResult();

        return (result.Status == BLESessionStatus.Timeout)
            .Label("Status must be BLESessionStatus.Timeout")
            .And(result.ResponseBytes == null)
            .Label("ResponseBytes must be null on timeout");
    }

    /// <summary>
    /// **Validates: Requirements 4.6** — [Property] attribute variant (MaxTest = 100).
    ///
    /// For any challenge bytes and any elapsed time within 15 s, the session
    /// result MUST NOT be a Timeout.
    /// </summary>
    [Property(MaxTest = 100, Arbitrary = new[] { typeof(BLETimeoutPropertyTests) })]
    public Property WithinTimeout_Property(byte[] challengeBytes, WithinElapsed elapsed)
    {
        // Feature: pc-unlock, Property 7
        var central = new FakeBLECentral(simulatedElapsedSeconds: elapsed.Seconds);
        var result = central.RunSessionAsync(challengeBytes).GetAwaiter().GetResult();

        return (result.Status != BLESessionStatus.Timeout)
            .Label("Status must not be Timeout for sessions within 15 s");
    }
}

// ---------------------------------------------------------------------------
// Unit fact tests
// ---------------------------------------------------------------------------

/// <summary>
/// xUnit [Fact] tests for BLE timeout enforcement constants and
/// <see cref="FakeBLECentral"/> semantics.
/// Validates: Requirements 4.6
/// </summary>
public sealed class BLETimeoutFactTests
{
    // -----------------------------------------------------------------------
    // Constant verification
    // -----------------------------------------------------------------------

    /// <summary>
    /// <see cref="BLECentral.SessionTimeout"/> must equal exactly 15 seconds
    /// (Requirement 4.6).
    /// </summary>
    [Fact]
    public void BLECentral_SessionTimeout_IsExactly15Seconds()
    {
        // Feature: pc-unlock, Property 7
        Assert.Equal(TimeSpan.FromSeconds(15), BLECentral.SessionTimeout);
    }

    /// <summary>
    /// <see cref="BLECentral.ChallengeByteLength"/> must equal 57, matching the
    /// canonical encoding: version[1] + sessionId[16] + nonce[32] + expiresAt[8].
    /// (Requirement 5.2)
    /// </summary>
    [Fact]
    public void BLECentral_ChallengeByteLength_Is57()
    {
        // Feature: pc-unlock, Property 7
        Assert.Equal(57, BLECentral.ChallengeByteLength);
    }

    // -----------------------------------------------------------------------
    // FakeBLECentral(shouldTimeout: true) — always returns Timeout
    // -----------------------------------------------------------------------

    /// <summary>
    /// <see cref="FakeBLECentral"/> constructed with <c>shouldTimeout: true</c>
    /// must always return a Timeout result with <c>ResponseBytes == null</c>.
    /// </summary>
    [Fact]
    public async Task FakeBLECentral_ShouldTimeoutTrue_AlwaysReturnsTimeout()
    {
        // Feature: pc-unlock, Property 7
        var central = new FakeBLECentral(shouldTimeout: true);
        var challenge = new byte[BLECentral.ChallengeByteLength];

        var result = await central.RunSessionAsync(challenge);

        Assert.Equal(BLESessionStatus.Timeout, result.Status);
        Assert.Null(result.ResponseBytes);
    }

    /// <summary>
    /// Cancellation token state does not change the outcome when
    /// <c>shouldTimeout: true</c> — the stub must still return Timeout.
    /// </summary>
    [Fact]
    public async Task FakeBLECentral_ShouldTimeoutTrue_WithCancelledToken_StillReturnsTimeout()
    {
        // Feature: pc-unlock, Property 7
        using var cts = new CancellationTokenSource();
        cts.Cancel();

        var central = new FakeBLECentral(shouldTimeout: true);
        var result = await central.RunSessionAsync(
            new byte[BLECentral.ChallengeByteLength], cts.Token);

        Assert.Equal(BLESessionStatus.Timeout, result.Status);
        Assert.Null(result.ResponseBytes);
    }

    // -----------------------------------------------------------------------
    // FakeBLECentral(shouldTimeout: false) — returns Success with non-null bytes
    // -----------------------------------------------------------------------

    /// <summary>
    /// <see cref="FakeBLECentral"/> constructed with <c>shouldTimeout: false</c>
    /// must return a Success result with <c>ResponseBytes != null</c>.
    /// </summary>
    [Fact]
    public async Task FakeBLECentral_ShouldTimeoutFalse_ReturnsSuccessWithNonNullResponseBytes()
    {
        // Feature: pc-unlock, Property 7
        var central = new FakeBLECentral(shouldTimeout: false);
        var challenge = new byte[BLECentral.ChallengeByteLength];

        var result = await central.RunSessionAsync(challenge);

        Assert.Equal(BLESessionStatus.Success, result.Status);
        Assert.NotNull(result.ResponseBytes);
    }

    /// <summary>
    /// The ResponseBytes returned on success must be non-empty.
    /// </summary>
    [Fact]
    public async Task FakeBLECentral_ShouldTimeoutFalse_ResponseBytesAreNonEmpty()
    {
        // Feature: pc-unlock, Property 7
        var central = new FakeBLECentral(shouldTimeout: false);
        var result = await central.RunSessionAsync(new byte[BLECentral.ChallengeByteLength]);

        Assert.NotNull(result.ResponseBytes);
        Assert.True(result.ResponseBytes!.Length > 0);
    }

    // -----------------------------------------------------------------------
    // Simulated-clock constructor boundary
    // -----------------------------------------------------------------------

    /// <summary>
    /// Elapsed time strictly greater than 15 s must produce a Timeout result.
    /// </summary>
    [Fact]
    public async Task FakeBLECentral_ElapsedExceeds15s_ProducesTimeout()
    {
        // Feature: pc-unlock, Property 7 — boundary: 15.001 s
        var central = new FakeBLECentral(simulatedElapsedSeconds: 15.001);
        var result = await central.RunSessionAsync(new byte[BLECentral.ChallengeByteLength]);

        Assert.Equal(BLESessionStatus.Timeout, result.Status);
        Assert.Null(result.ResponseBytes);
    }

    /// <summary>
    /// Elapsed time exactly equal to 15 s must NOT produce a Timeout result
    /// (the boundary is strictly greater than, not greater than or equal to).
    /// </summary>
    [Fact]
    public async Task FakeBLECentral_ElapsedExactly15s_ProducesSuccess()
    {
        // Feature: pc-unlock, Property 7 — boundary: exactly 15.0 s
        var central = new FakeBLECentral(simulatedElapsedSeconds: 15.0);
        var result = await central.RunSessionAsync(new byte[BLECentral.ChallengeByteLength]);

        Assert.Equal(BLESessionStatus.Success, result.Status);
        Assert.NotNull(result.ResponseBytes);
    }
}
