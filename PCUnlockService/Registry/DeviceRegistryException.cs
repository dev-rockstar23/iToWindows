// Feature: pc-unlock
// DeviceRegistryException — thrown when Device Registry operations fail.
// Requirements: 3.4, 9.2

namespace PCUnlockService.Registry;

/// <summary>
/// Thrown when a <see cref="DeviceRegistry"/> operation cannot be completed.
/// </summary>
public sealed class DeviceRegistryException : Exception
{
    /// <inheritdoc/>
    public DeviceRegistryException(string message) : base(message) { }

    /// <inheritdoc/>
    public DeviceRegistryException(string message, Exception inner) : base(message, inner) { }
}
