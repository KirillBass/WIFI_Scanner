using System.Globalization;
using Avalonia.Controls;
using Avalonia.Input;
using ScottPlot;
using WirelessSecurityAnalyzer.App.Controls;
using WirelessSecurityAnalyzer.App.ViewModels;
using WirelessSecurityAnalyzer.Core.Models;

namespace WirelessSecurityAnalyzer.App.Views;

public partial class ChannelsView : PlotViewBase
{
    private const string HoverHint = "Наведите курсор на кривую, чтобы увидеть SSID, MAC-адрес, канал и RSSI.";
    private ChannelAnalysisSnapshot? _renderedAnalysis;
    private readonly List<(ScottPlot.Plottables.Scatter Series, ChannelSpectrumCurve Curve)> _series = [];
    private bool _hasRendered;

    public ChannelsView()
    {
        InitializeComponent();
        ChannelPlot.PointerMoved += OnPlotPointerMoved;
        ChannelPlot.PointerExited += (_, _) => ResetHover();
    }

    protected override ScottPlot.Avalonia.AvaPlot Chart => ChannelPlot;
    protected override string DataProperty => nameof(ChannelsViewModel.Analysis);

    protected override void ConfigureAxes()
    {
        var plot = ChannelPlot.Plot;
        plot.XLabel("Канал");
        plot.HideLegend();
    }

    protected override void UpdatePlot()
    {
        var analysis = (DataContext as ChannelsViewModel)?.Analysis;
        if (_hasRendered && ReferenceEquals(analysis, _renderedAnalysis)) return;
        _hasRendered = true;
        _renderedAnalysis = analysis;
        var plot = ChannelPlot.Plot;
        plot.Clear();
        _series.Clear();
        ResetHover();
        double left = 2400, right = 2488, bottom = -100, top = -20;
        if (analysis?.Spectrum is { Count: > 0 } spectrum)
        {
            left = spectrum.Min(c => c.FrequenciesMhz[0]) - 5;
            right = spectrum.Max(c => c.FrequenciesMhz[^1]) + 5;
            // Show the 2.4 GHz candidate grid as well as all detected contours.
            if (analysis.Band == WifiBand.Ghz2_4 && analysis.Channels.Count > 0)
            {
                left = Math.Min(left, analysis.Channels.Min(c => c.CenterFrequencyMhz) - 15);
                right = Math.Max(right, analysis.Channels.Max(c => c.CenterFrequencyMhz) + 15);
            }
            bottom = Math.Min(bottom, spectrum.Min(c => c.RssiDbm.Min()));
            top = Math.Max(top, spectrum.Max(c => c.AccessPoint.RssiDbm) + 5);
            foreach (var curve in spectrum)
            {
                var series = plot.Add.Scatter(curve.FrequenciesMhz.ToArray(), curve.RssiDbm.ToArray());
                // Add.Scatter assigns colors from ScottPlot's palette.
                series.LineWidth = 2;
                series.MarkerSize = 0;
                series.LegendText = Describe(curve);
                _series.Add((series, curve));
            }
        }
        else if (analysis?.Channels is { Count: > 0 } channels)
        {
            left = channels.Min(c => c.CenterFrequencyMhz) - 15;
            right = channels.Max(c => c.CenterFrequencyMhz) + 15;
        }
        plot.Axes.Bottom.TickGenerator = new ChannelTicks(analysis);
        plot.Axes.SetLimitsX(left, right);
        plot.Axes.SetLimitsY(bottom, top);
        ChannelPlot.Refresh();
    }

    private void OnPlotPointerMoved(object? sender, PointerEventArgs e)
    {
        if (!IsAttached || _series.Count == 0) return;
        var position = e.GetPosition(ChannelPlot);
        var scale = ChannelPlot.DisplayScale;
        var pixel = new ScottPlot.Pixel((float)(position.X * scale), (float)(position.Y * scale));
        var plot = ChannelPlot.Plot;
        var coordinates = plot.GetCoordinates(pixel);
        ChannelSpectrumCurve? selected = null;
        double closest = double.PositiveInfinity;
        foreach (var (series, curve) in _series)
        {
            // A new scatter receives its axes during rendering. Ignore hover before its first frame.
            if (series.Axes.XAxis is null || series.Axes.YAxis is null) continue;
            var hit = series.GetNearest(coordinates, plot.LastRender, 12 * scale);
            if (!hit.IsReal) continue;
            var hitPixel = plot.GetPixel(hit.Coordinates);
            var distance = Math.Pow(pixel.X - hitPixel.X, 2) + Math.Pow(pixel.Y - hitPixel.Y, 2);
            if (distance >= closest) continue;
            closest = distance;
            selected = curve;
        }
        CurveDetails.Text = selected is null ? HoverHint : Describe(selected);
        ToolTip.SetTip(ChannelPlot, selected is null ? null : Describe(selected));
    }

    private void ResetHover()
    {
        CurveDetails.Text = HoverHint;
        ToolTip.SetTip(ChannelPlot, null);
    }

    private static string Describe(ChannelSpectrumCurve curve)
    {
        var ap = curve.AccessPoint;
        var ssid = ap.IsHidden || string.IsNullOrEmpty(ap.Ssid) ? "Скрытая сеть" : ap.Ssid;
        return $"{ssid} · {ap.Bssid} · канал {ap.Channel} · {ap.FrequencyMhz:0.#} МГц · {ap.RssiDbm} dBm";
    }

    private sealed class ChannelTicks(ChannelAnalysisSnapshot? analysis) : ITickGenerator
    {
        // Reserve space for labels under detected curves before labeling other channel centers.
        private readonly Tick[] _channels = analysis is null ? [] : analysis.Spectrum
            .Select(curve => (Frequency: curve.AccessPoint.FrequencyMhz, curve.AccessPoint.Channel))
            .OrderBy(point => point.Frequency)
            .Concat(analysis.Channels.Select(channel => (Frequency: channel.CenterFrequencyMhz, channel.Channel)))
            .DistinctBy(point => point.Frequency)
            .Select(point => Tick.Major(point.Frequency, point.Channel.ToString(CultureInfo.InvariantCulture)))
            .ToArray();

        public Tick[] Ticks { get; private set; } = [];
        public int MaxTickCount { get; set; } = int.MaxValue;

        public void Regenerate(CoordinateRange range, Edge edge, PixelLength size, Paint paint, LabelStyle labelStyle)
        {
            var visible = _channels.Where(tick => range.Contains(tick.Position)).Take(MaxTickCount).ToArray();
            if (visible.Length <= 1 || size.Length <= 0)
            {
                Ticks = visible;
                return;
            }

            var unitsPerPixel = range.Length / size.Length;
            var labeled = new List<(double Position, double HalfWidth)>();
            var ticks = new List<Tick>(visible.Length);
            foreach (var tick in visible)
            {
                var halfWidth = (labelStyle.Measure(tick.Label, paint).Size.Width + 4) * unitsPerPixel / 2;
                if (labeled.Any(label => Math.Abs(label.Position - tick.Position) < label.HalfWidth + halfWidth))
                    ticks.Add(Tick.Minor(tick.Position));
                else
                {
                    labeled.Add((tick.Position, halfWidth));
                    ticks.Add(tick);
                }
            }
            Ticks = ticks.OrderBy(tick => tick.Position).ToArray();
        }
    }
}
