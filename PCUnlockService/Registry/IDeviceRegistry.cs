// Feature: pc-unlock
// IDeviceRegistry — contract for the DPAPI-encrypted Device Registry.
// Requirements: 3.4, 3.5, 8.3, 9.2, 9.4

using PCUnlockService.Pairing;

namespace PCUnlockService.Registry;

/// <summary>
/// Manages the persistent, DPAPI-encrypted store of <see cref="DeviceRecord"/>
/// entries for all paired iPhones.
/// </summary>
public interface IDeviceRegistry
{
    /// <summary>Reads and returns all device records. Returns an empty list if the store is empty.</summary>
    IReadOnlyList<DeviceRecord> ReadAll();

    /// <summary>Atomically replaces all records with <paramref name="records"/>.</summary>
    void Write(IReadOnlyList<DeviceRecord> records);

    /// <summary>Appends a new <paramref name="record"/> to the registry.</summary>
    void Append(DeviceRecord record);

    /// <summary>
    /// Removes the record identified by <paramref name="deviceId"/>.
    /// Throws <see cref="DeviceRegistryException"/> if not found or if rollback fails.
    /// </summary>
    void Remove(Guid deviceId);

    /// <summary>Returns <c>true</c> if a record with <paramref name="deviceId"/> exists.</summary>
    bool Contains(Guid deviceId);

    /// <summary>Returns the record for <paramref name="deviceId"/>, or <c>null</c> if not found.</summary>
    DeviceRecord? Get(Guid deviceId);

    /// <summary>
    /// Verifies the integrity of the store by decrypting, parsing, and
    /// validating all records. Returns <c>true</c> if everything is valid.
    /// </summary>
    bool VerifyIntegrity();
}
