using System.Globalization;
using Avalonia;
using Avalonia.Controls;
using Avalonia.Media;

namespace WirelessSecurityAnalyzer.App.Controls;

/// <summary>Reusable presentation of measured RSSI; does not infer RSSI from link quality.</summary>
public sealed class SignalStrengthControl : Control
{
    public static readonly StyledProperty<int> RssiDbmProperty = AvaloniaProperty.Register<SignalStrengthControl, int>(nameof(RssiDbm), -100);
    static SignalStrengthControl() => AffectsRender<SignalStrengthControl>(RssiDbmProperty);
    public int RssiDbm { get => GetValue(RssiDbmProperty); set => SetValue(RssiDbmProperty, value); }
    protected override Size MeasureOverride(Size availableSize) => new(125, 26);

    public override void Render(DrawingContext context)
    {
        base.Render(context);
        var active = this.FindResource("SignalBrush") as IBrush;
        var muted = this.FindResource("MutedBrush") as IBrush;
        var textBrush = this.FindResource("TextBrush") as IBrush;
        var bars = RssiDbm >= -45 ? 4 : RssiDbm >= -60 ? 3 : RssiDbm >= -75 ? 2 : RssiDbm >= -90 ? 1 : 0;
        for (var i = 0; i < 4; i++)
            context.DrawRectangle(i < bars ? active : muted, null, new Rect(i * 7, 23 - (i + 1) * 5, 5, (i + 1) * 5), 1, 1);
        var text = new FormattedText($"{RssiDbm} dBm", CultureInfo.GetCultureInfo("ru-RU"),
            FlowDirection.LeftToRight, new Typeface("Inter, Segoe UI, sans-serif"), 13, textBrush);
        context.DrawText(text, new Point(36, 4));
    }
}
