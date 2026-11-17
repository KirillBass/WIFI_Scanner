using System.Globalization;
using Avalonia;
using Avalonia.Controls;
using Avalonia.Data.Converters;
using Avalonia.Media;

namespace WirelessSecurityAnalyzer.App.Controls;

public sealed class SiteRowBrushConverter : IValueConverter
{
    private static readonly IBrush Found = new SolidColorBrush(Color.Parse("#E3F0E4"));
    private static readonly IBrush SelectedFound = new SolidColorBrush(Color.Parse("#CCE4CF"));
    public object Convert(object? value, Type targetType, object? parameter, CultureInfo culture)
    {
        if (value is true) return parameter is null ? Found : SelectedFound;
        var resource = parameter switch
        {
            "selected" => "TableViewRowBackgroundSelected",
            "pointer" => "TableViewRowBackgroundPointerOver",
            "pressed" => "TableViewRowBackgroundPressed",
            "selected-pointer" => "TableViewRowBackgroundSelectedPointerOver",
            "selected-pressed" => "TableViewRowBackgroundSelectedPressed",
            _ => null
        };
        return resource is not null && Application.Current?.FindResource(resource) is IBrush brush
            ? brush : AvaloniaProperty.UnsetValue;
    }
    public object ConvertBack(object? value, Type targetType, object? parameter, CultureInfo culture) => throw new NotSupportedException();
}
