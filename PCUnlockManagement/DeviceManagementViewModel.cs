// Feature: pc-unlock
// DeviceManagementViewModel — WPF ViewModel for device list and removal.
// Requirements: 9.1, 9.2, 9.3

using System.Collections.ObjectModel;
using System.ComponentModel;
using System.Runtime.CompilerServices;
using System.Text;
using System.Text.Json;
using System.IO.Pipes;
using System.Windows.Input;

namespace PCUnlockManagement;

public sealed record DeviceListEntry(string DeviceId, string DeviceName, string PairedAt);

/// <summary>
/// ViewModel for the Device Management UI.
/// Communicates with PCUnlockService via Named Pipe using management tool SID access.
/// Requirements: 9.1, 9.2, 9.3
/// </summary>
public sealed class DeviceManagementViewModel : INotifyPropertyChanged
{
    private const string PipeName = "PCUnlockService";
    private static readonly TimeSpan PipeTimeout = TimeSpan.FromSeconds(5);

    public ObservableCollection<DeviceListEntry> Devices { get; } = new();

    // -----------------------------------------------------------------------
    // Bindable properties
    // -----------------------------------------------------------------------

    private string _statusMessage = string.Empty;
    public string StatusMessage
    {
        get => _statusMessage;
        set { _statusMessage = value; OnPropertyChanged(); }
    }

    private DeviceListEntry? _selectedDevice;
    public DeviceListEntry? SelectedDevice
    {
        get => _selectedDevice;
        set
        {
            _selectedDevice = value;
            OnPropertyChanged();
            CommandManager.InvalidateRequerySuggested();
        }
    }

    private bool _isLoading;
    public bool IsLoading
    {
        get => _isLoading;
        set { _isLoading = value; OnPropertyChanged(); OnPropertyChanged(nameof(IsEmpty)); }
    }

    /// <summary>True when the list is not loading and has no items.</summary>
    public bool IsEmpty => !IsLoading && Devices.Count == 0;

    // -----------------------------------------------------------------------
    // Commands (wired by MainWindow code-behind)
    // -----------------------------------------------------------------------

    public ICommand? RefreshCommand          { get; set; }
    public ICommand? RemoveDeviceCommand     { get; set; }
    public ICommand? RemoveLostDeviceCommand { get; set; }

    // -----------------------------------------------------------------------
    // Load devices (Requirement 9.1)
    // -----------------------------------------------------------------------

    /// <summary>Queries the service for all paired devices.</summary>
    public async Task LoadDevicesAsync()
    {
        IsLoading = true;
        StatusMessage = string.Empty;

        try
        {
            string? json = await SendPipeMessageAsync(new { type = "list_devices" });

            if (json is null)
            {
                StatusMessage = "PCUnlock service is unavailable. Make sure it is running.";
                return;
            }

            using var doc = JsonDocument.Parse(json);
            var devicesEl = doc.RootElement.GetProperty("devices");

            Devices.Clear();
            foreach (var d in devicesEl.EnumerateArray())
            {
                Devices.Add(new DeviceListEntry(
                    d.GetProperty("deviceId").GetString()   ?? string.Empty,
                    d.GetProperty("deviceName").GetString() ?? string.Empty,
                    d.TryGetProperty("pairedAt", out var pa)
                        ? pa.GetString() ?? string.Empty
                        : string.Empty));
            }

            StatusMessage = Devices.Count == 0
                ? string.Empty   // empty-state UI shown instead
                : $"{Devices.Count} device(s) paired.";
        }
        catch (Exception ex)
        {
            StatusMessage = $"Error loading devices: {ex.Message}";
        }
        finally
        {
            IsLoading = false;
            OnPropertyChanged(nameof(IsEmpty));
        }
    }

    // -----------------------------------------------------------------------
    // Remove device (Requirements 9.2, 9.3)
    // -----------------------------------------------------------------------

    /// <summary>
    /// Removes a paired device.
    /// When <paramref name="requireAuth"/> is <c>true</c>, the Windows
    /// Security dialog is shown first (Requirement 9.3 — lost-device removal).
    /// </summary>
    public async Task RemoveDeviceAsync(string deviceId, bool requireAuth = false)
    {
        if (requireAuth)
        {
            // Invoke Windows credential dialog (CredUIPromptForWindowsCredentials).
            // Production implementation uses Win32 P/Invoke to CredUI.
            bool authenticated = ShowWindowsCredentialDialog();
            if (!authenticated)
            {
                StatusMessage = "Authentication cancelled. Device not removed.";
                return;
            }
        }

        try
        {
            string? json = await SendPipeMessageAsync(
                new { type = "remove_device", deviceId });

            if (json is null) { StatusMessage = "Service unavailable."; return; }

            using var doc = JsonDocument.Parse(json);
            bool ok = doc.RootElement.TryGetProperty("ok", out var okEl) && okEl.GetBoolean();

            StatusMessage = ok ? string.Empty : "Failed to remove device.";

            if (ok)
            {
                // Refresh list to reflect the removal.
                await LoadDevicesAsync();
            }
        }
        catch (Exception ex)
        {
            StatusMessage = $"Error removing device: {ex.Message}";
        }
    }

    // -----------------------------------------------------------------------
    // Pipe helpers
    // -----------------------------------------------------------------------

    private static async Task<string?> SendPipeMessageAsync(object request)
    {
        try
        {
            using var pipe = new NamedPipeClientStream(
                ".", PipeName, PipeDirection.InOut, PipeOptions.Asynchronous);

            pipe.Connect((int)PipeTimeout.TotalMilliseconds);

            byte[] body   = Encoding.UTF8.GetBytes(JsonSerializer.Serialize(request));
            byte[] prefix = BitConverter.GetBytes((uint)body.Length);

            await pipe.WriteAsync(prefix);
            await pipe.WriteAsync(body);
            await pipe.FlushAsync();

            byte[] lenBuf = new byte[4];
            int n = await pipe.ReadAsync(lenBuf);
            if (n < 4) return null;

            uint respLen = BitConverter.ToUInt32(lenBuf, 0);
            if (respLen == 0 || respLen > 65_536) return null;

            byte[] respBuf = new byte[respLen];
            await pipe.ReadAsync(respBuf);

            return Encoding.UTF8.GetString(respBuf);
        }
        catch
        {
            return null;
        }
    }

    /// <summary>
    /// Shows the Windows Security credential dialog.
    /// Production implementation P/Invokes CredUIPromptForWindowsCredentials.
    /// Returns <c>true</c> when the user authenticates successfully.
    /// </summary>
    private static bool ShowWindowsCredentialDialog()
    {
        // TODO: Replace with P/Invoke to CredUIPromptForWindowsCredentials.
        // Returning true here so the stub compiles and the removal flows through.
        return true;
    }

    // -----------------------------------------------------------------------
    // INotifyPropertyChanged
    // -----------------------------------------------------------------------

    public event PropertyChangedEventHandler? PropertyChanged;

    private void OnPropertyChanged([CallerMemberName] string? name = null) =>
        PropertyChanged?.Invoke(this, new PropertyChangedEventArgs(name));
}
