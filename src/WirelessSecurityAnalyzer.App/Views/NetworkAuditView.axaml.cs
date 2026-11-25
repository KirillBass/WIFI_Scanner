using Avalonia.Controls;
using Avalonia.Input.Platform;
using Avalonia.Interactivity;
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
            Subscribe(false);
            _viewModel = DataContext as NetworkAuditViewModel;
            Subscribe(true);
            ArrangeDetails();
        };
        DetachedFromVisualTree += (_, _) =>
        {
            Subscribe(false);
            if (_viewModel is not null) _viewModel.Catalog.IsExpanded = false;
        };
        AttachedToVisualTree += (_, _) =>
        {
            Subscribe(false);
            Subscribe(true);
            ArrangeDetails();
        };
    }
    private void OnStateChanged(object? sender, PropertyChangedEventArgs e)
    {
        if (e.PropertyName is nameof(NetworkAuditViewModel.IsDetailsExpanded) or nameof(ResourceCatalogViewModel.IsExpanded)) ArrangeDetails();
    }
    private void Subscribe(bool listen)
    {
        if (_viewModel is null) return;
        if (listen)
        {
            _viewModel.PropertyChanged += OnStateChanged;
            _viewModel.Catalog.PropertyChanged += OnStateChanged;
        }
        else
        {
            _viewModel.PropertyChanged -= OnStateChanged;
            _viewModel.Catalog.PropertyChanged -= OnStateChanged;
        }
    }
    private async void CopyResourcePath(object? sender, RoutedEventArgs e)
    {
        var catalog = _viewModel?.Catalog;
        var path = catalog?.SelectedEntry?.RemotePath ?? catalog?.CurrentPath;
        if (!string.IsNullOrEmpty(path) && TopLevel.GetTopLevel(this)?.Clipboard is { } clipboard)
            await clipboard.SetTextAsync(path);
    }
    private void ArrangeDetails()
    {
        var visible = _viewModel?.IsDetailsExpanded == true;
        var catalog = _viewModel?.Catalog.IsExpanded == true;
        var wide = Bounds.Width >= (catalog ? 940 : 1100);
        ResultsLayout.ColumnDefinitions = new ColumnDefinitions(visible && wide ? catalog ? "*,8,470" : "*,8,350" : "*");
        ResultsLayout.RowDefinitions = new RowDefinitions(visible && !wide ? catalog ? "*,8,2*" : "2*,8,*" : "*");
        Grid.SetColumn(AuditDetailsPanel, visible && wide ? 2 : 0);
        Grid.SetRow(AuditDetailsPanel, visible && !wide ? 2 : 0);
    }
}
