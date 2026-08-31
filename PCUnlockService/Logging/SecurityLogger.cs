// Feature: pc-unlock
// SecurityLogger — wraps Windows Application Event Log for structured security events.
// Requirements: 8.4, 8.5, 10.1, 10.2, 10.3, 10.4, 10.5

using System.Diagnostics;

namespace PCUnlockService.Logging;

/// <summary>
/// Writes structured XML-formatted security events to the Windows Application
/// Event Log under the "PCUnlock" event source.
/// <para>
/// Operates in fire-and-forget mode — any failure to write (e.g. Event Log full
/// or unavailable) is silently swallowed, and the service continues operating.
/// Logging resumes automatically on the next call (Requirement 10.5).
/// </para>
/// <para>
/// NEVER includes: private key bytes, raw nonce values, biometric data,
/// passwords, PINs, or ECDSA signature bytes (Requirement 10.4).
/// </para>
/// </summary>
public sealed class SecurityLogger : ISecurityLogger
{
    private readonly string _eventSourceName;

    /// <summary>
    /// Creates a <see cref="SecurityLogger"/> writing to the given
    /// <paramref name="eventSourceName"/> in the Application Event Log.
    /// </summary>
    /// <param name="eventSourceName">
    /// Windows Event Log source name. Defaults to <c>"PCUnlock"</c>.
    /// </param>
    public SecurityLogger(string eventSourceName = "PCUnlock")
    {
        if (string.IsNullOrWhiteSpace(eventSourceName))
            throw new ArgumentException("Event source name must not be empty.", nameof(eventSourceName));

        _eventSourceName = eventSourceName;
    }

    // -------------------------------------------------------------------------
    // ISecurityLogger
    // -------------------------------------------------------------------------

    /// <inheritdoc/>
    public void LogUnlockAttempt(string deviceId, string outcome, string? failureReason = null)
    {
        // Requirement 10.4: deviceId is non-secret; outcome and reason are
        // human-readable codes — no key material, nonces, or biometrics.
        string xml = BuildXml(
            "UnlockAttempt",
            ("Timestamp",     DateTimeOffset.UtcNow.ToString("o")),
            ("DeviceId",      Sanitise(deviceId)),
            ("Outcome",       Sanitise(outcome)),
            ("FailureReason", Sanitise(failureReason ?? string.Empty)));

        WriteEvent(xml);
    }

    /// <inheritdoc/>
    public void LogPairingEvent(string deviceId, string outcome)
    {
        string xml = BuildXml(
            "PairingEvent",
            ("Timestamp", DateTimeOffset.UtcNow.ToString("o")),
            ("DeviceId",  Sanitise(deviceId)),
            ("Outcome",   Sanitise(outcome)));

        WriteEvent(xml);
    }

    /// <inheritdoc/>
    public void LogNonceRejection(string sessionId, string rejectionReason)
    {
        // Requirement 10.3: log sessionId and rejection reason only — never
        // the raw nonce value or signature bytes.
        string xml = BuildXml(
            "NonceRejection",
            ("Timestamp",       DateTimeOffset.UtcNow.ToString("o")),
            ("SessionId",       Sanitise(sessionId)),
            ("RejectionReason", Sanitise(rejectionReason)));

        WriteEvent(xml);
    }

    // -------------------------------------------------------------------------
    // Private helpers
    // -------------------------------------------------------------------------

    /// <summary>
    /// Writes <paramref name="xmlData"/> to the Windows Application Event Log.
    /// Any failure is swallowed (fire-and-forget, Requirement 10.5).
    /// </summary>
    private void WriteEvent(string xmlData)
    {
        try
        {
            EventLog.WriteEntry(
                _eventSourceName,
                xmlData,
                EventLogEntryType.Information);
        }
        catch
        {
            // Swallow all exceptions — Event Log unavailability must not
            // affect service operation (Requirement 10.5).
        }
    }

    /// <summary>
    /// Builds a structured XML event string with the given <paramref name="eventType"/>
    /// and key/value pairs.
    /// </summary>
    private static string BuildXml(string eventType, params (string Key, string Value)[] fields)
    {
        var sb = new System.Text.StringBuilder();
        sb.Append("<Event><Type>").Append(XmlEscape(eventType)).Append("</Type>");
        foreach (var (key, value) in fields)
        {
            sb.Append('<').Append(XmlEscape(key)).Append('>')
              .Append(XmlEscape(value))
              .Append("</").Append(XmlEscape(key)).Append('>');
        }
        sb.Append("</Event>");
        return sb.ToString();
    }

    /// <summary>XML-escapes a string to prevent injection into the event data.</summary>
    private static string XmlEscape(string value) =>
        value
            .Replace("&",  "&amp;")
            .Replace("<",  "&lt;")
            .Replace(">",  "&gt;")
            .Replace("\"", "&quot;")
            .Replace("'",  "&apos;");

    /// <summary>
    /// Strips or trims a value for safe logging. Returns an empty string for null.
    /// </summary>
    private static string Sanitise(string? value) =>
        (value ?? string.Empty).Trim();
}
