// Feature: pc-unlock
// SecurityLogEntry — structured event types for the Windows Event Log.
// Requirements: 8.4, 8.5, 10.1, 10.2, 10.3, 10.4, 10.5

namespace PCUnlockService.Logging;

/// <summary>Identifies the kind of security event logged.</summary>
public enum SecurityEventKind
{
    UnlockAttempt,
    PairingEvent,
    NonceRejection,
}

/// <summary>Data for an unlock attempt log entry (Requirement 10.1).</summary>
public sealed record UnlockAttemptEntry(
    DateTimeOffset Timestamp,
    string DeviceId,
    string Outcome,
    string? FailureReason);

/// <summary>Data for a pairing event log entry (Requirement 10.2).</summary>
public sealed record PairingEventEntry(
    DateTimeOffset Timestamp,
    string DeviceId,
    string Outcome);

/// <summary>Data for a nonce rejection log entry (Requirement 10.3).</summary>
public sealed record NonceRejectionEntry(
    DateTimeOffset Timestamp,
    string SessionId,
    string RejectionReason);
