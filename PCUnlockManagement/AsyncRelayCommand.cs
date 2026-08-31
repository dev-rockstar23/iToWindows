// Feature: pc-unlock
// AsyncRelayCommand — ICommand implementation that wraps an async delegate.

using System.Windows.Input;

namespace PCUnlockManagement;

/// <summary>
/// A lightweight <see cref="ICommand"/> that wraps an async void delegate.
/// Disables itself while the operation is running to prevent double-invocation.
/// </summary>
public sealed class AsyncRelayCommand : ICommand
{
    private readonly Func<Task> _execute;
    private readonly Func<bool>? _canExecute;
    private bool _isRunning;

    public AsyncRelayCommand(Func<Task> execute, Func<bool>? canExecute = null)
    {
        _execute    = execute;
        _canExecute = canExecute;
    }

    public event EventHandler? CanExecuteChanged
    {
        add    => CommandManager.RequerySuggested += value;
        remove => CommandManager.RequerySuggested -= value;
    }

    public bool CanExecute(object? parameter) =>
        !_isRunning && (_canExecute?.Invoke() ?? true);

    public async void Execute(object? parameter)
    {
        if (!CanExecute(parameter)) return;
        _isRunning = true;
        CommandManager.InvalidateRequerySuggested();

        try   { await _execute(); }
        finally
        {
            _isRunning = false;
            CommandManager.InvalidateRequerySuggested();
        }
    }
}
