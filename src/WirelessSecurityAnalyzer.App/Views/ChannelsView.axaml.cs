using System.ComponentModel;
using System.Globalization;
using Avalonia;
using Avalonia.Controls;
using Avalonia.Input;
using Avalonia.Media;
using Avalonia.Threading;
using WirelessSecurityAnalyzer.App.ViewModels;
using WirelessSecurityAnalyzer.Core.Models;

namespace WirelessSecurityAnalyzer.App.Views;

public partial class ChannelsView : UserControl
{
    private const string HoverHint = "Наведите курсор на кривую, чтобы увидеть SSID, BSSID, канал и RSSI.";
    private ChannelsViewModel? _viewModel;
    private ChannelAnalysisSnapshot? _renderedAnalysis;
    private readonly List<(ScottPlot.Plottables.Scatter Series, ChannelSpectrumCurve Curve)> _series = [];
    private bool _attached, _updateQueued, _hasRendered;

    public ChannelsView()
    {
        InitializeComponent();
        DataContextChanged += (_, _) => { if (_attached) BindViewModel(); };
        ChannelPlot.PointerMoved += OnPlotPointerMoved;
        ChannelPlot.PointerExited += (_, _) => ResetHover();
    }

    protected override void OnAttachedToVisualTree(VisualTreeAttachmentEventArgs e)
    {
        base.OnAttachedToVisualTree(e);
        _attached = true;
        var plot = ChannelPlot.Plot;
        plot.FigureBackground.Color = ThemeColor("CardBrush");
        plot.DataBackground.Color = ThemeColor("WindowBrush");
        plot.Axes.Color(ThemeColor("TextBrush"));
        plot.Grid.MajorLineColor = ThemeColor("BorderBrush");
        plot.XLabel("Центральная частота, МГц");
        plot.YLabel("RSSI, dBm");
        plot.HideLegend();
        plot.Axes.Bottom.TickGenerator = new ScottPlot.TickGenerators.NumericAutomatic
        {
            LabelFormatter = frequency => frequency.ToString("0.#", CultureInfo.GetCultureInfo("ru-RU"))
        };
        BindViewModel();
    }

    protected override void OnDetachedFromVisualTree(VisualTreeAttachmentEventArgs e)
    {
        _attached = false;
        if (_viewModel is not null) _viewModel.PropertyChanged -= OnViewModelChanged;
        _viewModel = null;
        base.OnDetachedFromVisualTree(e);
    }

    private void BindViewModel()
    {
        if (_viewModel is not null) _viewModel.PropertyChanged -= OnViewModelChanged;
        _viewModel = DataContext as ChannelsViewModel;
        if (_viewModel is not null) _viewModel.PropertyChanged += OnViewModelChanged;
        QueuePlotUpdate();
    }

    private void OnViewModelChanged(object? sender, PropertyChangedEventArgs e)
    {
        if (e.PropertyName is nameof(ChannelsViewModel.Analysis) or null or "") QueuePlotUpdate();
    }

    private void QueuePlotUpdate()
    {
        if (_updateQueued || !_attached) return;
        _updateQueued = true;
        Dispatcher.UIThread.Post(() =>
        {
            _updateQueued = false;
            if (_attached) UpdatePlot();
        }, DispatcherPriority.Background);
    }

    private void UpdatePlot()
    {
        var analysis = _viewModel?.Analysis;
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
        plot.Axes.SetLimitsX(left, right);
        plot.Axes.SetLimitsY(bottom, top);
        ChannelPlot.Refresh();
    }

    private void OnPlotPointerMoved(object? sender, PointerEventArgs e)
    {
        if (!_attached || _series.Count == 0) return;
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

    private ScottPlot.Color ThemeColor(string key)
    {
        var brush = this.FindResource(key) as SolidColorBrush
            ?? throw new InvalidOperationException($"Missing theme brush: {key}");
        return ScottPlot.Color.FromHex($"#{brush.Color.R:X2}{brush.Color.G:X2}{brush.Color.B:X2}");
    }
}
