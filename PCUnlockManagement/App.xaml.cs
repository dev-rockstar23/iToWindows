// Feature: pc-unlock
// App.xaml.cs — WPF application entry point for PCUnlock Management UI.
// Requirements: 9.1, 9.2, 9.3

using System.Windows;

namespace PCUnlockManagement;

/// <summary>
/// Interaction logic for App.xaml — PCUnlock Management UI entry point.
/// </summary>
public partial class App : Application
{
    protected override void OnStartup(StartupEventArgs e)
    {
        base.OnStartup(e);
        // Global unhandled exception guard — surface gracefully rather than crash silently.
        DispatcherUnhandledException += (_, args) =>
        {
            MessageBox.Show(
                $"An unexpected error occurred:\n\n{args.Exception.Message}",
                "PCUnlock Management",
                MessageBoxButton.OK,
                MessageBoxImage.Error);
            args.Handled = true;
        };
    }
}
