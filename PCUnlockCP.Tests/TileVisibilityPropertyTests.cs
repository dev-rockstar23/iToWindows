// Feature: pc-unlock, Property 20
// TileVisibilityPropertyTests — tile visibility tracks registry state.
// Validates: Requirements 9.5

using FsCheck;
using FsCheck.Fluent;
using FsCheck.Xunit;
using PCUnlockCP;
using Xunit;

namespace PCUnlockCP.Tests;

/// <summary>
/// Property 20: For any Device Registry state transitioning from non-empty to
/// empty (last device removed), the CP tile visibility signal changes to hidden.
/// The tile must be visible when any paired device exists and the service is up.
/// Validates: Requirements 9.5
/// </summary>
public sealed class TileVisibilityPropertyTests
{
    [Fact]
    public void GetCount_ServiceAvailable_OneDevice_Returns1()
    {
        // Feature: pc-unlock, Property 20
        var cp = new CredentialProviderStub();
        Assert.Equal(1, cp.GetCount(serviceAvailable: true, pairedDeviceCount: 1));
    }

    [Fact]
    public void GetCount_ServiceAvailable_MultipleDevices_Returns1()
    {
        // Feature: pc-unlock, Property 20
        var cp = new CredentialProviderStub();
        Assert.Equal(1, cp.GetCount(serviceAvailable: true, pairedDeviceCount: 5));
    }

    [Fact]
    public void GetCount_ServiceUnavailable_Returns0()
    {
        // Feature: pc-unlock, Property 20
        var cp = new CredentialProviderStub();
        Assert.Equal(0, cp.GetCount(serviceAvailable: false, pairedDeviceCount: 3));
    }

    [Fact]
    public void GetCount_NoPairedDevices_Returns0()
    {
        // Feature: pc-unlock, Property 20
        var cp = new CredentialProviderStub();
        Assert.Equal(0, cp.GetCount(serviceAvailable: true, pairedDeviceCount: 0));
    }

    [Fact]
    public void GetCount_ServiceUnavailable_NoPairedDevices_Returns0()
    {
        // Feature: pc-unlock, Property 20
        var cp = new CredentialProviderStub();
        Assert.Equal(0, cp.GetCount(serviceAvailable: false, pairedDeviceCount: 0));
    }

    /// <summary>
    /// Tile must always be hidden when pairedDeviceCount == 0, regardless of
    /// service availability.
    /// Validates: Requirements 9.5
    /// </summary>
    [Property(MaxTest = 100)]
    public Property TileHidden_WhenNoDevicesPaired()
    {
        // Feature: pc-unlock, Property 20
        return Prop.ForAll(
            Gen.Elements(true, false).ToArbitrary(),
            (bool serviceAvailable) =>
            {
                var cp = new CredentialProviderStub();
                int count = cp.GetCount(serviceAvailable, pairedDeviceCount: 0);
                return (count == 0)
                    .Label($"Tile must be hidden (count=0) when no devices paired (serviceAvailable={serviceAvailable})");
            });
    }

    /// <summary>
    /// Tile must always be hidden when service is unavailable, regardless of
    /// device count.
    /// Validates: Requirements 1.2, 9.5
    /// </summary>
    [Property(MaxTest = 100)]
    public Property TileHidden_WhenServiceUnavailable()
    {
        // Feature: pc-unlock, Property 20
        return Prop.ForAll(
            Gen.Choose(0, 100).ToArbitrary(),
            deviceCount =>
            {
                var cp = new CredentialProviderStub();
                int count = cp.GetCount(serviceAvailable: false, pairedDeviceCount: deviceCount);
                return (count == 0)
                    .Label($"Tile must be hidden when service is unavailable (devices={deviceCount})");
            });
    }

    /// <summary>
    /// Tile must be visible (count=1) when service is available and at least
    /// one device is paired.
    /// Validates: Requirements 9.5
    /// </summary>
    [Property(MaxTest = 100)]
    public Property TileVisible_WhenServiceAvailableAndDevicesPaired()
    {
        // Feature: pc-unlock, Property 20
        return Prop.ForAll(
            Gen.Choose(1, 20).ToArbitrary(),
            deviceCount =>
            {
                var cp = new CredentialProviderStub();
                int count = cp.GetCount(serviceAvailable: true, pairedDeviceCount: deviceCount);
                return (count == 1)
                    .Label($"Tile must be visible (count=1) when service is up and {deviceCount} device(s) paired");
            });
    }
}
