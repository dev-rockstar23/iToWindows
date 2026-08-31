// Feature: pc-unlock
// Minimal logging abstraction used by PCUnlockService components.
// Keeping this separate from Microsoft.Extensions.Logging allows the service
// to swap logging backends without changing component code.

namespace PCUnlockService.Logging;

/// <summary>Severity levels for structured log entries.</summary>
public enum LogLevel
{
    Debug,
    Information,
    Warning,
    Error,
    Critical
}

/// <summary>
/// Minimal logging contract consumed by PCUnlockService components.
/// </summary>
public interface ILogger
{
    /// <summary>Writes a log entry at the specified <paramref name="level"/>.</summary>
    void Log(LogLevel level, string message);
}

/// <summary>
/// No-op logger — discards all messages.  Useful for unit tests that do not
/// need to inspect log output.
/// </summary>
public sealed class NullLogger : ILogger
{
    /// <summary>Shared singleton instance.</summary>
    public static readonly NullLogger Instance = new();

    private NullLogger() { }

    /// <inheritdoc/>
    public void Log(LogLevel level, string message) { }
}
