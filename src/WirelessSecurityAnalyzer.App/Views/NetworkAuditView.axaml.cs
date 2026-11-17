using Avalonia.Controls;
using System.ComponentModel;
using WirelessSecurityAnalyzer.App.ViewModels;

namespace WirelessSecurityAnalyzer.App.Views;

public partial class NetworkAuditView : UserControl
{
    private NetworkAuditViewModel? _viewModel;
    public NetworkAuditView()
    {
        InitializeComponent();
        SizeChanged += (_, _) => ArrangeDetails();
        DataContextChanged += (_, _) =>
        {
            if (_viewModel is not null) _viewModel.PropertyChanged -= OnStateChanged;
            _viewModel = DataContext as NetworkAuditViewModel;
            if (_viewModel is not null) _viewModel.PropertyChanged += OnStateChanged;
            ArrangeDetails();
        };
        DetachedFromVisualTree += (_, _) =>
        {
            if (_viewModel is not null) _viewModel.PropertyChanged -= OnStateChanged;
        };
        AttachedToVisualTree += (_, _) =>
        {
            if (_viewModel is not null) { _viewModel.PropertyChanged -= OnStateChanged; _viewModel.PropertyChanged += OnStateChanged; }
            ArrangeDetails();
        };
    }
    private void OnStateChanged(object? sender, PropertyChangedEventArgs e)
    {
        if (e.PropertyName == nameof(NetworkAuditViewModel.IsDetailsExpanded)) ArrangeDetails();
    }
    private void ArrangeDetails()
    {
        var visible = _viewModel?.IsDetailsExpanded == true;
        var wide = Bounds.Width >= 1100;
        ResultsLayout.ColumnDefinitions = new ColumnDefinitions(visible && wide ? "*,8,350" : "*");
        ResultsLayout.RowDefinitions = new RowDefinitions(visible && !wide ? "2*,8,*" : "*");
        Grid.SetColumn(AuditDetailsPanel, visible && wide ? 2 : 0);
        Grid.SetRow(AuditDetailsPanel, visible && !wide ? 2 : 0);
    }
}
