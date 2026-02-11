using System.Globalization;
using System.Windows;
using System.Windows.Data;
using System.Windows.Media;
using W365ConnectivityTool.Models;

namespace W365ConnectivityTool.Converters;

/// <summary>
/// Converts TestStatus to a SolidColorBrush for UI display.
/// </summary>
public class StatusToColorConverter : IValueConverter
{
    public object Convert(object value, Type targetType, object parameter, CultureInfo culture)
    {
        if (value is string colorHex)
            return new SolidColorBrush((Color)ColorConverter.ConvertFromString(colorHex));

        return Brushes.Gray;
    }

    public object ConvertBack(object value, Type targetType, object parameter, CultureInfo culture)
        => throw new NotSupportedException();
}

/// <summary>
/// Converts bool to Visibility (true = Visible, false = Collapsed).
/// </summary>
public class BoolToVisibilityConverter : IValueConverter
{
    public object Convert(object value, Type targetType, object parameter, CultureInfo culture)
    {
        if (value is bool b)
            return b ? Visibility.Visible : Visibility.Collapsed;
        return Visibility.Collapsed;
    }

    public object ConvertBack(object value, Type targetType, object parameter, CultureInfo culture)
        => throw new NotSupportedException();
}

/// <summary>
/// Inverts a boolean value.
/// </summary>
public class InverseBoolConverter : IValueConverter
{
    public object Convert(object value, Type targetType, object parameter, CultureInfo culture)
        => value is bool b ? !b : false;

    public object ConvertBack(object value, Type targetType, object parameter, CultureInfo culture)
        => throw new NotSupportedException();
}

/// <summary>
/// Returns Visibility.Visible if string is not empty.
/// </summary>
public class StringToVisibilityConverter : IValueConverter
{
    public object Convert(object value, Type targetType, object parameter, CultureInfo culture)
    {
        return string.IsNullOrEmpty(value as string) ? Visibility.Collapsed : Visibility.Visible;
    }

    public object ConvertBack(object value, Type targetType, object parameter, CultureInfo culture)
        => throw new NotSupportedException();
}

/// <summary>
/// Converts TestStatus to background color for the status badge.
/// </summary>
public class StatusToBackgroundConverter : IValueConverter
{
    public object Convert(object value, Type targetType, object parameter, CultureInfo culture)
    {
        if (value is TestStatus status)
        {
            return status switch
            {
                TestStatus.Passed => new SolidColorBrush(Color.FromRgb(0xDF, 0xF6, 0xDD)),   // Light green
                TestStatus.Warning => new SolidColorBrush(Color.FromRgb(0xFF, 0xF4, 0xCE)),  // Light orange
                TestStatus.Failed => new SolidColorBrush(Color.FromRgb(0xFD, 0xE7, 0xE9)),   // Light red
                TestStatus.Running => new SolidColorBrush(Color.FromRgb(0xDE, 0xEC, 0xF9)),  // Light blue
                TestStatus.Skipped => new SolidColorBrush(Color.FromRgb(0xF3, 0xF2, 0xF1)),  // Light gray
                TestStatus.Error => new SolidColorBrush(Color.FromRgb(0xFD, 0xE7, 0xE9)),    // Light red
                _ => new SolidColorBrush(Color.FromRgb(0xF3, 0xF2, 0xF1))
            };
        }
        return Brushes.Transparent;
    }

    public object ConvertBack(object value, Type targetType, object parameter, CultureInfo culture)
        => throw new NotSupportedException();
}

/// <summary>
/// Converts TestStatus to foreground color for status text.
/// </summary>
public class StatusToForegroundConverter : IValueConverter
{
    public object Convert(object value, Type targetType, object parameter, CultureInfo culture)
    {
        if (value is TestStatus status)
        {
            return status switch
            {
                TestStatus.Passed => new SolidColorBrush(Color.FromRgb(0x10, 0x7C, 0x10)),
                TestStatus.Warning => new SolidColorBrush(Color.FromRgb(0xC4, 0x6B, 0x00)),
                TestStatus.Failed => new SolidColorBrush(Color.FromRgb(0xD1, 0x34, 0x38)),
                TestStatus.Running => new SolidColorBrush(Color.FromRgb(0x00, 0x78, 0xD4)),
                TestStatus.Error => new SolidColorBrush(Color.FromRgb(0xD1, 0x34, 0x38)),
                _ => new SolidColorBrush(Color.FromRgb(0x8A, 0x88, 0x86))
            };
        }
        return Brushes.Gray;
    }

    public object ConvertBack(object value, Type targetType, object parameter, CultureInfo culture)
        => throw new NotSupportedException();
}
