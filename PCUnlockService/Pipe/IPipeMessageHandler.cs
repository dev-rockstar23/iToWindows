// Feature: pc-unlock
// IPipeMessageHandler — handler interface for Named Pipe messages.
// Requirements: 7.3, 8.1

namespace PCUnlockService.Pipe;

/// <summary>
/// Processes an incoming pipe message and optionally returns a response to
/// serialize back to the caller.
/// </summary>
public interface IPipeMessageHandler
{
    /// <summary>
    /// Handles an incoming pipe message.
    /// </summary>
    /// <param name="messageType">The <c>type</c> field from the JSON payload.</param>
    /// <param name="jsonPayload">The full UTF-8 JSON payload string.</param>
    /// <param name="ct">Cancellation token.</param>
    /// <returns>
    /// A response object to serialize and send back, or <c>null</c> if no
    /// response should be sent.
    /// </returns>
    Task<object?> HandleAsync(string messageType, string jsonPayload, CancellationToken ct);
}
