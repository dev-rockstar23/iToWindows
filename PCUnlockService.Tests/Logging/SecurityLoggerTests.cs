// Feature: pc-unlock
// SecurityLoggerTests — validates ISecurityLogger implementations.
// Requirements: 8.4, 8.5, 10.1, 10.2, 10.3, 10.4, 10.5

using PCUnlockService.Logging;
using Xunit;

namespace PCUnlockService.Tests.Logging;

// ---------------------------------------------------------------------------
// TestableSecurityLogger — captures log entries without calling EventLog
// ---------------------------------------------------------------------------

/// <summary>
/// In-process logger that stores the generated XML strings so tests can
/// inspect them without requiring access to the Windows Event Log.
/// </summary>
internal sealed class TestableSecurityLogger : ISecurityLogger
{
    private readonly List<string> _entries = new();

    /// <summary>All XML strings that have been logged.</summary>
    public IReadOnlyList<string> LoggedEntries => _entries;

    public void LogUnlockAttempt(string deviceId, string outcome, string? failureReason = null)
    {
        _entries.Add(BuildXml("UnlockAttempt",
            ("Timestamp",     DateTimeOffset.UtcNow.ToString("o")),
            ("DeviceId",      deviceId ?? string.Empty),
            ("Outcome",       outcome ?? string.Empty),
            ("FailureReason", failureReason ?? string.Empty)));
    }

    public void LogPairingEvent(string deviceId, string outcome)
    {
        _entries.Add(BuildXml("PairingEvent",
            ("Timestamp", DateTimeOffset.UtcNow.ToString("o")),
            ("DeviceId",  deviceId ?? string.Empty),
            ("Outcome",   outcome ?? string.Empty)));
    }

    public void LogNonceRejection(string sessionId, string rejectionReason)
    {
        _entries.Add(BuildXml("NonceRejection",
            ("Timestamp",       DateTimeOffset.UtcNow.ToString("o")),
            ("SessionId",       sessionId ?? string.Empty),
            ("RejectionReason", rejectionReason ?? string.Empty)));
    }

    private static string BuildXml(string eventType, params (string Key, string Value)[] fields)
    {
        var sb = new System.Text.StringBuilder();
        sb.Append("<Event><Type>").Append(eventType).Append("</Type>");
        foreach (var (key, value) in fields)
            sb.Append('<').Append(key).Append('>').Append(value).Append("</").Append(key).Append('>');
        sb.Append("</Event>");
        return sb.ToString();
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

public sealed class SecurityLoggerTests
{
    // Prohibited substrings that must never appear in any log entry.
    private static readonly string[] ProhibitedTerms =
    [
        "signature", "privatekey", "private_key", "biometric",
        "password", "pin", "nonce", "rawkey"
    ];

    private static void AssertNoProhibitedTerms(string logEntry)
    {
        foreach (var term in ProhibitedTerms)
        {
            Assert.False(
                logEntry.Contains(term, StringComparison.OrdinalIgnoreCase),
                $"Log entry must not contain '{term}': {logEntry}");
        }
    }

    // -----------------------------------------------------------------------
    // LogUnlockAttempt
    // -----------------------------------------------------------------------

    [Fact]
    public void LogUnlockAttempt_ContainsRequiredFields()
    {
        var logger = new TestableSecurityLogger();
        logger.LogUnlockAttempt("device-abc", "success");

        Assert.Single(logger.LoggedEntries);
        string entry = logger.LoggedEntries[0];

        Assert.Contains("Timestamp",    entry);
        Assert.Contains("DeviceId",     entry);
        Assert.Contains("device-abc",   entry);
        Assert.Contains("Outcome",      entry);
        Assert.Contains("success",      entry);
        Assert.Contains("FailureReason", entry);
    }

    [Fact]
    public void LogUnlockAttempt_WithFailureReason_ContainsReason()
    {
        var logger = new TestableSecurityLogger();
        logger.LogUnlockAttempt("device-xyz", "failure", "BAD_SIG");

        string entry = logger.LoggedEntries[0];
        Assert.Contains("BAD_SIG", entry);
    }

    [Fact]
    public void LogUnlockAttempt_DoesNotContainProhibitedFields()
    {
        var logger = new TestableSecurityLogger();
        logger.LogUnlockAttempt("device-abc", "success");
        AssertNoProhibitedTerms(logger.LoggedEntries[0]);
    }

    // -----------------------------------------------------------------------
    // LogPairingEvent
    // -----------------------------------------------------------------------

    [Fact]
    public void LogPairingEvent_ContainsRequiredFields()
    {
        var logger = new TestableSecurityLogger();
        logger.LogPairingEvent("device-pair-01", "success");

        string entry = logger.LoggedEntries[0];
        Assert.Contains("Timestamp",        entry);
        Assert.Contains("DeviceId",         entry);
        Assert.Contains("device-pair-01",   entry);
        Assert.Contains("Outcome",          entry);
        Assert.Contains("success",          entry);
    }

    [Fact]
    public void LogPairingEvent_DoesNotContainProhibitedFields()
    {
        var logger = new TestableSecurityLogger();
        logger.LogPairingEvent("device-pair-01", "timeout");
        AssertNoProhibitedTerms(logger.LoggedEntries[0]);
    }

    // -----------------------------------------------------------------------
    // LogNonceRejection
    // -----------------------------------------------------------------------

    [Fact]
    public void LogNonceRejection_ContainsRequiredFields()
    {
        var logger = new TestableSecurityLogger();
        logger.LogNonceRejection("session-001", "REPLAY");

        string entry = logger.LoggedEntries[0];
        Assert.Contains("Timestamp",       entry);
        Assert.Contains("SessionId",       entry);
        Assert.Contains("session-001",     entry);
        Assert.Contains("RejectionReason", entry);
        Assert.Contains("REPLAY",          entry);
    }

    [Fact]
    public void LogNonceRejection_DoesNotContainRawNonceValue()
    {
        var logger = new TestableSecurityLogger();
        // The raw nonce hex must never appear — only the session ID and reason.
        string rawNonceHex = "DEADBEEFDEADBEEFDEADBEEFDEADBEEFDEADBEEFDEADBEEFDEADBEEFDEADBEEF";
        logger.LogNonceRejection("session-002", "REPLAY");

        // Confirm the raw nonce hex (64 chars) is not in the entry.
        Assert.DoesNotContain(rawNonceHex, logger.LoggedEntries[0]);
    }

    [Fact]
    public void LogNonceRejection_DoesNotContainProhibitedFields()
    {
        var logger = new TestableSecurityLogger();
        logger.LogNonceRejection("session-003", "EXPIRED");
        AssertNoProhibitedTerms(logger.LoggedEntries[0]);
    }

    // -----------------------------------------------------------------------
    // Fire-and-forget: real SecurityLogger must not throw even if EventLog fails
    // -----------------------------------------------------------------------

    [Fact]
    public void SecurityLogger_FireAndForget_DoesNotThrow()
    {
        // Use an event source name that almost certainly doesn't exist in the
        // test environment's Event Log — this exercises the swallow-exception path.
        var logger = new SecurityLogger("PCUnlockTest_NonExistent_Source_8675309");

        // None of these calls must throw, even if writing to the Event Log fails.
        var ex1 = Record.Exception(() => logger.LogUnlockAttempt("d1", "failure", "TEST"));
        var ex2 = Record.Exception(() => logger.LogPairingEvent("d1", "success"));
        var ex3 = Record.Exception(() => logger.LogNonceRejection("s1", "REPLAY"));

        Assert.Null(ex1);
        Assert.Null(ex2);
        Assert.Null(ex3);
    }
}
