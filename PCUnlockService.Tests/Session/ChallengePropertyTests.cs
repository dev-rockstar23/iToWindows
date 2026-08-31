// Feature: pc-unlock, Property 9
// Challenge field correctness — property-based tests.
// Validates: Requirements 5.2
//
// Property 9: For any call to generateChallenge():
//   - SessionId is unique among active sessions
//   - Nonce is exactly 32 bytes
//   - ExpiresAt == generation time + 60 s (±1 s)

using System.Buffers.Binary;
using FsCheck;
using FsCheck.Fluent;
using FsCheck.Xunit;
using PCUnlockService.Crypto;
using PCUnlockService.Session;
using Xunit;

namespace PCUnlockService.Tests.Session;

// ---------------------------------------------------------------------------
// Generators for Property 9
// ---------------------------------------------------------------------------

internal static class ChallengeGenerators
{
    /// <summary>
    /// Generates non-empty device ID strings using FsCheck's built-in
    /// <see cref="NonEmptyString"/> arbitrary, then extracts the underlying
    /// string value — exactly as specified in the task.
    /// </summary>
    public static Arbitrary<string> NonEmptyDeviceId() =>
        Arb.Generate<NonEmptyString>()
           .Select(s => s.Get)
           .ToArbitrary();
}

// ---------------------------------------------------------------------------
// Unit [Fact] tests — example-based verification
// ---------------------------------------------------------------------------

/// <summary>
/// Unit (example-based) tests for <see cref="ChallengeGenerator"/> and
/// <see cref="UnlockSession"/>. Validates: Requirements 5.2
/// </summary>
public sealed class ChallengeFactTests
{
    /// <summary>
    /// <see cref="ChallengeGenerator.EncodeChallenge"/> MUST produce exactly
    /// 57 bytes: version[1] + sessionId[16] + nonce[32] + expiresAt[8].
    /// </summary>
    [Fact]
    public void EncodeChallenge_ProducesExactly57Bytes()
    {
        // Feature: pc-unlock, Property 9
        var session = ChallengeGenerator.GenerateChallenge("device-1");
        byte[] encoded = ChallengeGenerator.EncodeChallenge(session);

        Assert.Equal(57, encoded.Length);
    }

    /// <summary>
    /// The first byte of the encoded challenge MUST be 1 (protocol version).
    /// </summary>
    [Fact]
    public void EncodeChallenge_FirstByte_IsVersion1()
    {
        // Feature: pc-unlock, Property 9
        var session = ChallengeGenerator.GenerateChallenge("device-1");
        byte[] encoded = ChallengeGenerator.EncodeChallenge(session);

        Assert.Equal((byte)ChallengeGenerator.ChallengeVersion, encoded[0]);
        Assert.Equal(1, encoded[0]);
    }

    /// <summary>
    /// The last 8 bytes of the encoded challenge MUST contain <c>ExpiresAt</c>
    /// encoded as a little-endian <see cref="long"/>.
    /// </summary>
    [Fact]
    public void EncodeChallenge_ExpiresAt_EncodedAsLittleEndian()
    {
        // Feature: pc-unlock, Property 9
        var session = ChallengeGenerator.GenerateChallenge("device-1");
        byte[] encoded = ChallengeGenerator.EncodeChallenge(session);

        long decodedExpiresAt = BinaryPrimitives.ReadInt64LittleEndian(encoded.AsSpan(49));

        Assert.Equal(session.ExpiresAt, decodedExpiresAt);
    }

    /// <summary>
    /// Two consecutive calls to <see cref="ChallengeGenerator.GenerateChallenge"/>
    /// MUST produce nonces that differ (uniqueness of nonces).
    /// </summary>
    [Fact]
    public void GenerateChallenge_TwoCalls_ProduceDifferentNonces()
    {
        // Feature: pc-unlock, Property 9
        var s1 = ChallengeGenerator.GenerateChallenge("device-1");
        var s2 = ChallengeGenerator.GenerateChallenge("device-1");

        Assert.False(s1.Nonce.SequenceEqual(s2.Nonce),
            "Two consecutive nonces must not be equal");
    }
}

// ---------------------------------------------------------------------------
// Property-based tests — Property 9 (FsCheck)
// ---------------------------------------------------------------------------

/// <summary>
/// Property-based tests for Challenge field correctness (Property 9).
/// Validates: Requirements 5.2 — minimum 100 iterations.
/// </summary>
public sealed class ChallengePropertyTests
{
    // -----------------------------------------------------------------------
    // Wrapper type for [Property(Arbitrary = ...)] approach
    // -----------------------------------------------------------------------

    /// <summary>Wrapper: a non-empty device ID string.</summary>
    public readonly record struct DeviceIdInput(string Value);

    /// <summary>FsCheck arbitrary for <see cref="DeviceIdInput"/>.</summary>
    public static Arbitrary<DeviceIdInput> ArbitraryDeviceId() =>
        Arb.Generate<NonEmptyString>()
           .Select(s => new DeviceIdInput(s.Get))
           .ToArbitrary();

    // -----------------------------------------------------------------------
    // Property 9a — nonce length, sessionId non-empty, expiresAt in [now+59, now+61]
    // -----------------------------------------------------------------------

    /// <summary>
    /// **Validates: Requirements 5.2**
    ///
    /// For any non-empty device ID string, a challenge produced by
    /// <see cref="ChallengeGenerator.GenerateChallenge"/> MUST satisfy:
    /// <list type="bullet">
    ///   <item><c>Nonce.Length == 32</c></item>
    ///   <item><c>SessionId != Guid.Empty</c></item>
    ///   <item><c>ExpiresAt</c> in <c>[now+59, now+61]</c></item>
    /// </list>
    /// </summary>
    [Property(MaxTest = 100, Arbitrary = new[] { typeof(ChallengePropertyTests) })]
    public Property GenerateChallenge_FieldsAreCorrect(DeviceIdInput input)
    {
        // Feature: pc-unlock, Property 9
        long before = DateTimeOffset.UtcNow.ToUnixTimeSeconds();
        var session = ChallengeGenerator.GenerateChallenge(input.Value);
        long after = DateTimeOffset.UtcNow.ToUnixTimeSeconds();

        bool nonceLength  = session.Nonce.Length == NonceGenerator.NonceLength;
        bool sessionIdSet = session.SessionId != Guid.Empty;

        // ExpiresAt must equal generation time + 60 s (± 1 s accounts for the
        // small window between recording 'before'/'after' and the call itself).
        long minExpiry = before + ChallengeGenerator.ChallengeTtlSeconds - 1;
        long maxExpiry = after  + ChallengeGenerator.ChallengeTtlSeconds + 1;
        bool expiryInRange = session.ExpiresAt >= minExpiry && session.ExpiresAt <= maxExpiry;

        return nonceLength
            .Label($"Nonce.Length must be {NonceGenerator.NonceLength} (was {session.Nonce.Length})")
            .And(sessionIdSet)
            .Label("SessionId must not be Guid.Empty")
            .And(expiryInRange)
            .Label($"ExpiresAt {session.ExpiresAt} must be in [{minExpiry}, {maxExpiry}]");
    }

    /// <summary>
    /// **Validates: Requirements 5.2** — Prop.ForAll variant.
    ///
    /// Same three assertions driven via <see cref="Prop.ForAll{T}"/> with
    /// explicit <see cref="Configuration"/> (MaxTest = 100).
    /// </summary>
    [Fact]
    public void Property9a_ChallengeFields_PropForAll()
    {
        // Feature: pc-unlock, Property 9
        var cfg = Configuration.QuickThrowOnFailure.WithMaxTest(100);

        var prop = Prop.ForAll(
            ChallengeGenerators.NonEmptyDeviceId(),
            deviceId =>
            {
                long before = DateTimeOffset.UtcNow.ToUnixTimeSeconds();
                var session = ChallengeGenerator.GenerateChallenge(deviceId);
                long after = DateTimeOffset.UtcNow.ToUnixTimeSeconds();

                bool nonceLength  = session.Nonce.Length == NonceGenerator.NonceLength;
                bool sessionIdSet = session.SessionId != Guid.Empty;

                long minExpiry = before + ChallengeGenerator.ChallengeTtlSeconds - 1;
                long maxExpiry = after  + ChallengeGenerator.ChallengeTtlSeconds + 1;
                bool expiryInRange = session.ExpiresAt >= minExpiry && session.ExpiresAt <= maxExpiry;

                return nonceLength
                    .Label($"Nonce.Length must be {NonceGenerator.NonceLength}")
                    .And(sessionIdSet)
                    .Label("SessionId must not be Guid.Empty")
                    .And(expiryInRange)
                    .Label($"ExpiresAt {session.ExpiresAt} not in [{minExpiry}, {maxExpiry}]");
            });

        prop.Check(cfg);
    }

    // -----------------------------------------------------------------------
    // Property 9b — two GenerateChallenge calls produce distinct SessionIds
    // -----------------------------------------------------------------------

    /// <summary>
    /// **Validates: Requirements 5.2**
    ///
    /// Any two calls to <see cref="ChallengeGenerator.GenerateChallenge"/> MUST
    /// produce sessions with distinct <see cref="UnlockSession.SessionId"/> values.
    /// </summary>
    [Property(MaxTest = 100, Arbitrary = new[] { typeof(ChallengePropertyTests) })]
    public Property TwoGenerateChallenges_ProduceDistinctSessionIds(DeviceIdInput input)
    {
        // Feature: pc-unlock, Property 9
        var s1 = ChallengeGenerator.GenerateChallenge(input.Value);
        var s2 = ChallengeGenerator.GenerateChallenge(input.Value);

        return (s1.SessionId != s2.SessionId)
            .Label($"SessionIds must be distinct (both were {s1.SessionId})");
    }

    /// <summary>
    /// **Validates: Requirements 5.2** — Prop.ForAll variant.
    ///
    /// Same distinct-SessionId assertion driven via <see cref="Prop.ForAll{T}"/>
    /// with explicit <see cref="Configuration"/> (MaxTest = 100).
    /// </summary>
    [Fact]
    public void Property9b_TwoChallenges_DistinctSessionIds_PropForAll()
    {
        // Feature: pc-unlock, Property 9
        var cfg = Configuration.QuickThrowOnFailure.WithMaxTest(100);

        var prop = Prop.ForAll(
            ChallengeGenerators.NonEmptyDeviceId(),
            deviceId =>
            {
                var s1 = ChallengeGenerator.GenerateChallenge(deviceId);
                var s2 = ChallengeGenerator.GenerateChallenge(deviceId);

                return (s1.SessionId != s2.SessionId)
                    .Label($"SessionIds must differ across two GenerateChallenge calls");
            });

        prop.Check(cfg);
    }
}
