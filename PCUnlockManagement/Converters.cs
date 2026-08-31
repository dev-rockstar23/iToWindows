// Feature: pc-unlock
// Converters.cs — WPF value converters for the Management UI.

using System.Globalization;
using System.Windows;
using System.Windows.Data;

namespace PCUnlockManagement;

/// <summary>
/// Returns <see cref="Visibility.Visible"/> when the bound string is
/// non-null and non-empty; <see cref="Visibility.Collapsed"/> otherwise.
/// Used to show/hide the status message banner.
/// </summary>
[ValueConversion(typeof(string), typeof(Visibility))]
public sealed class StringToVisibilityConverter : IValueConverter
{
    public object Convert(object? value, Type targetType,
                          object? parameter, CultureInfo culture) =>
        string.IsNullOrEmpty(value as string)
            ? Visibility.Collapsed
            : Visibility.Visible;

    public object ConvertBack(object? value, Type targetType,
                              object? parameter, CultureInfo culture) =>
        throw new NotSupportedException();
}

/// <summary>
/// Returns <see cref="Visibility.Visible"/> when the bound <see cref="bool"/>
/// is <c>true</c>; <see cref="Visibility.Collapsed"/> otherwise.
/// Used to show the empty-state panel and loading indicator.
/// </summary>
[ValueConversion(typeof(bool), typeof(Visibility))]
public sealed class BoolToVisibilityConverter : IValueConverter
{
    public object Convert(object? value, Type targetType,
                          object? parameter, CultureInfo culture) =>
        value is true ? Visibility.Visible : Visibility.Collapsed;

    public object ConvertBack(object? value, Type targetType,
                              object? parameter, CultureInfo culture) =>
        throw new NotSupportedException();
}
