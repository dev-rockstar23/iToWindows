// Feature: pc-unlock
// MainWindow.xaml.cs — code-behind for the PCUnlock Management UI.
// Requirements: 9.1, 9.2, 9.3

using System.Windows;
using System.Windows.Input;

namespace PCUnlockManagement;

/// <summary>
/// Interaction logic for MainWindow.xaml.
/// Binds to <see cref="DeviceManagementViewModel"/> and wires up
/// commands to WPF ICommand implementations.
/// </summary>
public partial class MainWindow : Window
{
    private readonly DeviceManagementViewModel _vm;

    public MainWindow()
    {
        InitializeComponent();

        _vm = new DeviceManagementViewModel();
        _vm.RefreshCommand          = new AsyncRelayCommand(RefreshAsync);
        _vm.RemoveDeviceCommand     = new AsyncRelayCommand(RemoveDeviceAsync,
                                          () => _vm.SelectedDevice is not null);
        _vm.RemoveLostDeviceCommand = new AsyncRelayCommand(RemoveLostDeviceAsync);

        DataContext = _vm;

        // Auto-load devices when the window opens.
        Loaded += async (_, _) => await _vm.LoadDevicesAsync();
    }

    // -----------------------------------------------------------------------
    // Command handlers
    // -----------------------------------------------------------------------

    private async Task RefreshAsync()
    {
        await _vm.LoadDevicesAsync();
        CommandManager.InvalidateRequerySuggested();
    }

    private async Task RemoveDeviceAsync()
    {
        var device = _vm.SelectedDevice;
        if (device is null) return;

        var confirm = MessageBox.Show(
            $"Remove \"{device.DeviceName}\" (…{device.DeviceId[^8..]})?{Environment.NewLine}" +
            "This device will no longer be able to unlock this PC.",
            "Remove Device",
            MessageBoxButton.YesNo,
            MessageBoxImage.Warning);

        if (confirm != MessageBoxResult.Yes) return;

        await _vm.RemoveDeviceAsync(device.DeviceId, requireAuth: false);
        CommandManager.InvalidateRequerySuggested();
    }

    private async Task RemoveLostDeviceAsync()
    {
        var device = _vm.SelectedDevice;
        if (device is null)
        {
            MessageBox.Show(
                "Select a device from the list first.",
                "Remove Lost Device",
                MessageBoxButton.OK,
                MessageBoxImage.Information);
            return;
        }

        // Requirement 9.3: re-authentication before removing a lost device.
        // The ViewModel calls CredUIPromptForWindowsCredentials internally.
        await _vm.RemoveDeviceAsync(device.DeviceId, requireAuth: true);
        CommandManager.InvalidateRequerySuggested();
    }
}
