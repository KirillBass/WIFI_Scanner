using System.ComponentModel;
using Avalonia;
using Avalonia.Controls;
using Avalonia.Media;
using Avalonia.Threading;
using WirelessSecurityAnalyzer.App.ViewModels;

namespace WirelessSecurityAnalyzer.App.Views;

public partial class SignalView : UserControl
{
    private SignalViewModel? _viewModel;
    private bool _attached;
    private bool _updateQueued;

    public SignalView()
    {
        InitializeComponent();
        DataContextChanged += (_, _) => { if (_attached) BindViewModel(); };
    }

    protected override void OnAttachedToVisualTree(VisualTreeAttachmentEventArgs e)
    {
        base.OnAttachedToVisualTree(e);
        _attached = true;
        var plot = SignalPlot.Plot;
        // DateTimeTicksBottom replaces the bottom axis, so style and label it afterwards.
        plot.Axes.DateTimeTicksBottom();
        plot.FigureBackground.Color = ThemeColor("CardBrush");
        plot.DataBackground.Color = ThemeColor("WindowBrush");
        plot.Axes.Color(ThemeColor("TextBrush"));
        plot.Grid.MajorLineColor = ThemeColor("BorderBrush");
        plot.YLabel("RSSI, dBm");
        plot.XLabel("Время");
        ((ScottPlot.TickGenerators.DateTimeAutomatic)plot.Axes.Bottom.TickGenerator).LabelFormatter =
            utc => DateTime.SpecifyKind(utc, DateTimeKind.Utc).ToLocalTime().ToString("HH:mm:ss");
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
        _viewModel = DataContext as SignalViewModel;
        if (_viewModel is not null) _viewModel.PropertyChanged += OnViewModelChanged;
        QueuePlotUpdate();
    }

    private void OnViewModelChanged(object? sender, PropertyChangedEventArgs e)
    {
        if (e.PropertyName is nameof(SignalViewModel.Samples) or null or "") QueuePlotUpdate();
    }

    private void QueuePlotUpdate()
    {
        if (_updateQueued || !_attached) return;
        _updateQueued = true;
        // Coalesce snapshot/statistic changes; AvaPlot.Refresh requests a UI repaint.
        Dispatcher.UIThread.Post(() =>
        {
            _updateQueued = false;
            if (!_attached) return;
            UpdatePlot();
        }, DispatcherPriority.Background);
    }

    private void UpdatePlot()
    {
        var samples = _viewModel?.Samples;
        var plot = SignalPlot.Plot;
        plot.Clear();
        var now = DateTime.UtcNow.ToOADate();
        var left = now - TimeSpan.FromSeconds(15).TotalDays;
        var right = now + TimeSpan.FromSeconds(15).TotalDays;
        double minimum = -100, maximum = -20;
        if (samples is { Count: > 0 })
        {
            var xs = samples.Select(sample => sample.Timestamp.UtcDateTime.ToOADate()).ToArray();
            var ys = samples.Select(sample => (double)sample.RssiDbm).ToArray();
            var series = plot.Add.Scatter(xs, ys);
            series.Color = ThemeColor("SignalBrush");
            series.LineWidth = 2;
            series.MarkerSize = 4;
            var padding = xs[^1] == xs[0] ? TimeSpan.FromSeconds(15).TotalDays :
                Math.Max(TimeSpan.FromSeconds(2).TotalDays, (xs[^1] - xs[0]) * .03);
            left = xs[0] - padding;
            right = xs[^1] + padding;
            minimum = Math.Min(minimum, ys.Min() - 5);
            maximum = Math.Max(maximum, ys.Max() + 5);
        }
        plot.Axes.SetLimitsX(left, right);
        plot.Axes.SetLimitsY(minimum, maximum);
        SignalPlot.Refresh();
    }

    private ScottPlot.Color ThemeColor(string key)
    {
        var brush = this.FindResource(key) as SolidColorBrush
            ?? throw new InvalidOperationException($"Missing theme brush: {key}");
        return ScottPlot.Color.FromHex($"#{brush.Color.R:X2}{brush.Color.G:X2}{brush.Color.B:X2}");
    }
}
