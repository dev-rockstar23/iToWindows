// Feature: pc-unlock
// CredentialProvider — implements the tile-visibility and status-message logic
// that backs the ICredentialProvider COM interface for the PCUnlock tile.
//
// Full COM in-process server registration is performed by the MSI/WiX installer
// custom action.  This class encapsulates all testable logic so the COM shim
// can delegate straight to it.
//
// Requirements: 1.1, 1.2, 7.1, 7.2, 7.8, 9.5

namespace PCUnlockCP;

// ---------------------------------------------------------------------------
// Tile-state model
// ---------------------------------------------------------------------------

/// The reason the PCUnlock tile is currently hidden (or visible).
public enum TileHideReason
{
    /// Tile is visible — service up and at least one device paired.
    None,
    /// The Named Pipe to PCUnlockService is not reachable.
    ServiceUnavailable,
    /// Service is reachable but the Device Registry is empty.
    NoDevicesPaired,
    /// Bluetooth is disabled or unavailable on this PC (Requirement 4.7).
    BleUnavailable,
}

/// Snapshot of everything the CP needs to decide tile visibility and the
/// status string shown below the tile.
public sealed record TileState(
    bool   ServiceAvailable,
    int    PairedDeviceCount,
    bool   BleAvailable)
{
    public static readonly TileState Default = new(
        ServiceAvailable:   false,
        PairedDeviceCount:  0,
        BleAvailable:       true);
}

// ---------------------------------------------------------------------------
// CredentialProvider (ICredentialProvider logic layer)
// ---------------------------------------------------------------------------

/// <summary>
/// Encapsulates all logic for the PCUnlock <c>ICredentialProvider</c>
/// implementation.
///
/// <para>
/// <b>GetCount</b> returns 1 when the Named Pipe service is reachable AND at
/// least one device is paired; returns 0 otherwise (Requirements 1.2, 9.5).
/// </para>
/// <para>
/// The provider MUST NOT be set as the default or exclusive provider
/// (Requirement 7.8).
/// </para>
/// <para>
/// COM registration is under:
/// <c>HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Authentication\
/// Credential Providers\{7B3E5A9C-2F4D-4A8B-9C1E-3D6F8A0B2E4C}</c>
/// (Requirement 7.2).
/// </para>
/// </summary>
public sealed class CredentialProviderStub
{
    // -----------------------------------------------------------------------
    // ICredentialProvider: GetCount
    // -----------------------------------------------------------------------

    /// <summary>
    /// Returns the tile count for the PCUnlock credential.
    /// <list type="bullet">
    ///   <item>Returns <c>1</c> when the service is available, BLE is on,
    ///     and at least one device is paired.</item>
    ///   <item>Returns <c>0</c> in all other cases so the tile is hidden
    ///     without affecting any other provider (Requirements 1.1, 1.2, 9.5).
    ///   </item>
    /// </list>
    /// </summary>
    public int GetCount(bool serviceAvailable, int pairedDeviceCount) =>
        serviceAvailable && pairedDeviceCount > 0 ? 1 : 0;

    /// <summary>
    /// Overload that accepts the full <see cref="TileState"/> snapshot,
    /// additionally gating on BLE availability (Requirement 4.7).
    /// </summary>
    public int GetCount(TileState state) =>
        state.ServiceAvailable && state.BleAvailable && state.PairedDeviceCount > 0 ? 1 : 0;

    // -----------------------------------------------------------------------
    // ICredentialProvider: GetFieldDescriptorAt
    // -----------------------------------------------------------------------

    /// <summary>
    /// Returns the field descriptor for the given field index.
    /// Field 0 = tile label.  Field 1 = status message.
    /// </summary>
    public (string fieldType, string label) GetFieldDescriptorAt(int fieldIndex) =>
        fieldIndex switch
        {
            0 => ("CPFT_LARGE_TEXT",  "Unlock with iPhone"),
            1 => ("CPFT_SMALL_TEXT",  string.Empty),
            _ => throw new ArgumentOutOfRangeException(nameof(fieldIndex))
        };

    // -----------------------------------------------------------------------
    // Status message
    // -----------------------------------------------------------------------

    /// <summary>
    /// Returns the user-visible status string to display in the tile's
    /// secondary field, reflecting the current <see cref="TileHideReason"/>.
    /// </summary>
    public string GetStatusMessage(TileState state)
    {
        if (!state.BleAvailable)
            return "Bluetooth is unavailable on this PC."; // Requirement 4.7

        if (!state.ServiceAvailable)
            return "PCUnlock service is unavailable."; // Requirement 1.2

        if (state.PairedDeviceCount == 0)
            return "No paired iPhones. Open PCUnlock to pair."; // Requirement 9.5

        return string.Empty; // tile is visible — no status needed
    }

    /// <summary>
    /// Classifies the current <see cref="TileState"/> into a
    /// <see cref="TileHideReason"/>.
    /// </summary>
    public TileHideReason GetHideReason(TileState state)
    {
        if (!state.BleAvailable)        return TileHideReason.BleUnavailable;
        if (!state.ServiceAvailable)    return TileHideReason.ServiceUnavailable;
        if (state.PairedDeviceCount == 0) return TileHideReason.NoDevicesPaired;
        return TileHideReason.None;
    }
}
