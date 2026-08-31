// Feature: pc-unlock, Property 21
// Feature: pc-unlock, Property 22
// Feature: pc-unlock, Property 23
//
// LogEntryCompletenessPropertyTests — property-based tests validating that
// each security log entry contains all required fields and none of the
// prohibited ones.
//
// Property 21: Log entry completeness — unlock attempts (Requirements 10.1, 10.4, 8.4, 8.5)
// Property 22: Log entry completeness — pairing events  (Requirements 10.2, 10.4)
// Property 23: Log entry completeness — nonce rejections (Requirements 10.3, 10.4)

using FsCheck;
using FsCheck.Fluent;
using FsCheck.Xunit;
using PCUnlockService.Logging;
using Xunit;

namespace PCUnlockService.Tests.Logging;

// ---------------------------------------------------------------------------
// Shared generators
// ---------------------------------------------------------------------------

internal static class LogPropertyGenerators
{
    /// <summary>Non-null, non-empty string arbitrary.</summary>
    public static Arbitrary<string> NonEmptyString() =>
        Arb.Generate<NonEmptyString>()
           .Select(s => s.Get)
           .ToArbitrary();

    /// <summary>Optional string arbitrary (null or non-empty).</summary>
    public static Arbitrary<string?> NullableNonEmptyString() =>
        Gen.OneOf(
            Gen.Constant<string?>(null),
            Arb.Generate<NonEmptyString>().Select<NonEmptyString, string?>(s => s.Get))
           .ToArbitrary();
}

// ===========================================================================
// Property 21 — Unlock attempt log entry completeness
// ===========================================================================

/// <summary>
/// Property 21: For any unlock attempt event, the log entry MUST contain
/// timestamp, deviceId, outcome, failure reason (if any); and MUST NOT
/// contain private key bytes, raw nonce, biometric data, passwords, PINs, or
/// ECDSA signature bytes.
/// Validates: Requirements 10.1, 10.4, 8.4, 8.5
/// </summary>
public sealed class UnlockAttemptLogCompletenessTests
{
    private static readonly string[] ProhibitedTerms =
    [
        "privatekey", "private_key", "biometric", "password",
        "pin", "rawsig", "signature_bytes", "nonce_raw"
    ];

    // -----------------------------------------------------------------------
    // Property 21 — for any deviceId × outcome × optional failureReason
    // -----------------------------------------------------------------------

    public readonly record struct UnlockLogInputs(string DeviceId, string Outcome, string? FailureReason);

    public static Arbitrary<UnlockLogInputs> ArbitraryUnlockLogInputs() =>
        (from deviceId in LogPropertyGenerators.NonEmptyString().Generator
         from outcome in LogPropertyGenerators.NonEmptyString().Generator
         from reason in LogPropertyGenerators.NullableNonEmptyString().Generator
         select new UnlockLogInputs(deviceId, outcome, reason))
        .ToArbitrary();

    /// <summary>
    /// For any unlock attempt, the log entry must contain Timestamp, DeviceId,
    /// Outcome, FailureReason fields and must not contain any prohibited terms.
    /// Validates: Requirements 10.1, 10.4, 8.4, 8.5
    /// </summary>
    [Property(MaxTest = 100, Arbitrary = new[] { typeof(UnlockAttemptLogCompletenessTests) })]
    public Property UnlockAttemptEntry_ContainsRequiredFields_NoProhibitedTerms(UnlockLogInputs inputs)
    {
        // Feature: pc-unlock, Property 21
        var logger = new TestableSecurityLogger();
        logger.LogUnlockAttempt(inputs.DeviceId, inputs.Outcome, inputs.FailureReason);

        string entry = logger.LoggedEntries[0];

        bool hasTimestamp     = entry.Contains("Timestamp");
        bool hasDeviceId      = entry.Contains("DeviceId") && entry.Contains(inputs.DeviceId);
        bool hasOutcome       = entry.Contains("Outcome")  && entry.Contains(inputs.Outcome);
        bool hasReasonField   = entry.Contains("FailureReason");
        bool noProhibited     = ProhibitedTerms.All(t =>
            !entry.Contains(t, StringComparison.OrdinalIgnoreCase));

        return hasTimestamp
            .Label("Entry must contain Timestamp field")
            .And(hasDeviceId)
            .Label("Entry must contain DeviceId and its value")
            .And(hasOutcome)
            .Label("Entry must contain Outcome and its value")
            .And(hasReasonField)
            .Label("Entry must contain FailureReason field")
            .And(noProhibited)
            .Label("Entry must not contain any prohibited terms");
    }

    [Fact]
    public void UnlockAttemptEntry_Success_ContainsAllFields_NoProhibited()
    {
        // Feature: pc-unlock, Property 21
        var logger = new TestableSecurityLogger();
        logger.LogUnlockAttempt("device-001", "success");
        string entry = logger.LoggedEntries[0];

        Assert.Contains("Timestamp",     entry);
        Assert.Contains("DeviceId",      entry);
        Assert.Contains("device-001",    entry);
        Assert.Contains("Outcome",       entry);
        Assert.Contains("success",       entry);
        Assert.Contains("FailureReason", entry);

        foreach (var term in ProhibitedTerms)
            Assert.DoesNotContain(term, entry, StringComparison.OrdinalIgnoreCase);
    }
}

// ===========================================================================
// Property 22 — Pairing event log entry completeness
// ===========================================================================

/// <summary>
/// Property 22: For any pairing event, the log entry MUST contain timestamp,
/// deviceId, outcome; and prohibited fields must be absent.
/// Validates: Requirements 10.2, 10.4
/// </summary>
public sealed class PairingEventLogCompletenessTests
{
    private static readonly string[] ProhibitedTerms =
    [
        "privatekey", "private_key", "biometric", "password",
        "pin", "rawsig", "signature_bytes", "nonce_raw"
    ];

    public readonly record struct PairingLogInputs(string DeviceId, string Outcome);

    public static Arbitrary<PairingLogInputs> ArbitraryPairingLogInputs() =>
        (from deviceId in LogPropertyGenerators.NonEmptyString().Generator
         from outcome in LogPropertyGenerators.NonEmptyString().Generator
         select new PairingLogInputs(deviceId, outcome))
        .ToArbitrary();

    /// <summary>
    /// For any pairing event, the log entry must contain Timestamp, DeviceId,
    /// Outcome and must not contain any prohibited terms.
    /// Validates: Requirements 10.2, 10.4
    /// </summary>
    [Property(MaxTest = 100, Arbitrary = new[] { typeof(PairingEventLogCompletenessTests) })]
    public Property PairingEventEntry_ContainsRequiredFields_NoProhibitedTerms(PairingLogInputs inputs)
    {
        // Feature: pc-unlock, Property 22
        var logger = new TestableSecurityLogger();
        logger.LogPairingEvent(inputs.DeviceId, inputs.Outcome);

        string entry = logger.LoggedEntries[0];

        bool hasTimestamp = entry.Contains("Timestamp");
        bool hasDeviceId  = entry.Contains("DeviceId") && entry.Contains(inputs.DeviceId);
        bool hasOutcome   = entry.Contains("Outcome")  && entry.Contains(inputs.Outcome);
        bool noProhibited = ProhibitedTerms.All(t =>
            !entry.Contains(t, StringComparison.OrdinalIgnoreCase));

        return hasTimestamp
            .Label("Entry must contain Timestamp")
            .And(hasDeviceId)
            .Label("Entry must contain DeviceId and its value")
            .And(hasOutcome)
            .Label("Entry must contain Outcome and its value")
            .And(noProhibited)
            .Label("Entry must not contain prohibited terms");
    }

    [Fact]
    public void PairingEventEntry_ContainsAllFields_NoProhibited()
    {
        // Feature: pc-unlock, Property 22
        var logger = new TestableSecurityLogger();
        logger.LogPairingEvent("device-pair-99", "success");
        string entry = logger.LoggedEntries[0];

        Assert.Contains("Timestamp",       entry);
        Assert.Contains("DeviceId",        entry);
        Assert.Contains("device-pair-99", entry);
        Assert.Contains("Outcome",         entry);
        Assert.Contains("success",         entry);

        foreach (var term in ProhibitedTerms)
            Assert.DoesNotContain(term, entry, StringComparison.OrdinalIgnoreCase);
    }
}

// ===========================================================================
// Property 23 — Nonce rejection log entry completeness
// ===========================================================================

/// <summary>
/// Property 23: For any nonce rejection event, the log entry MUST contain
/// timestamp, sessionId, rejection reason; raw nonce value and signature bytes
/// must be absent.
/// Validates: Requirements 10.3, 10.4
/// </summary>
public sealed class NonceRejectionLogCompletenessTests
{
    private static readonly string[] ProhibitedTerms =
    [
        "privatekey", "private_key", "biometric", "password",
        "pin", "rawsig", "signature_bytes", "nonce_raw"
    ];

    public readonly record struct NonceLogInputs(string SessionId, string RejectionReason);

    public static Arbitrary<NonceLogInputs> ArbitraryNonceLogInputs() =>
        (from sessionId in LogPropertyGenerators.NonEmptyString().Generator
         from reason in LogPropertyGenerators.NonEmptyString().Generator
         select new NonceLogInputs(sessionId, reason))
        .ToArbitrary();

    /// <summary>
    /// For any nonce rejection event, the log entry must contain Timestamp,
    /// SessionId, RejectionReason and must not contain any prohibited terms.
    /// Validates: Requirements 10.3, 10.4
    /// </summary>
    [Property(MaxTest = 100, Arbitrary = new[] { typeof(NonceRejectionLogCompletenessTests) })]
    public Property NonceRejectionEntry_ContainsRequiredFields_NoProhibitedTerms(NonceLogInputs inputs)
    {
        // Feature: pc-unlock, Property 23
        var logger = new TestableSecurityLogger();
        logger.LogNonceRejection(inputs.SessionId, inputs.RejectionReason);

        string entry = logger.LoggedEntries[0];

        bool hasTimestamp = entry.Contains("Timestamp");
        bool hasSessionId = entry.Contains("SessionId") && entry.Contains(inputs.SessionId);
        bool hasReason    = entry.Contains("RejectionReason") && entry.Contains(inputs.RejectionReason);
        bool noProhibited = ProhibitedTerms.All(t =>
            !entry.Contains(t, StringComparison.OrdinalIgnoreCase));

        return hasTimestamp
            .Label("Entry must contain Timestamp")
            .And(hasSessionId)
            .Label("Entry must contain SessionId and its value")
            .And(hasReason)
            .Label("Entry must contain RejectionReason and its value")
            .And(noProhibited)
            .Label("Entry must not contain prohibited terms");
    }

    [Fact]
    public void NonceRejectionEntry_ContainsAllFields_NoRawNonce()
    {
        // Feature: pc-unlock, Property 23
        var logger = new TestableSecurityLogger();
        logger.LogNonceRejection("session-abc", "REPLAY");
        string entry = logger.LoggedEntries[0];

        Assert.Contains("Timestamp",       entry);
        Assert.Contains("SessionId",       entry);
        Assert.Contains("session-abc",     entry);
        Assert.Contains("RejectionReason", entry);
        Assert.Contains("REPLAY",          entry);

        // Raw nonce hex must never appear.
        string rawNonceHex = new string('A', 64); // 64-char hex = 32 bytes
        Assert.DoesNotContain(rawNonceHex, entry);

        foreach (var term in ProhibitedTerms)
            Assert.DoesNotContain(term, entry, StringComparison.OrdinalIgnoreCase);
    }
}
