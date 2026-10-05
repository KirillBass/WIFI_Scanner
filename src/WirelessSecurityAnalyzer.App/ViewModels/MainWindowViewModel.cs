using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;

namespace WirelessSecurityAnalyzer.App.ViewModels;

public sealed record NavigationItem(string Title, ViewModelBase Page);

public sealed partial class MainWindowViewModel : ViewModelBase
{
    private readonly AccessPointsViewModel _accessPoints;
    public MainWindowViewModel(DashboardViewModel dashboard, AccessPointsViewModel accessPoints,
        ChannelsViewModel channels, SignalViewModel signal, DevicesViewModel devices, SettingsViewModel settings)
    {
        _accessPoints = accessPoints;
        Navigation = [new("Обзор", dashboard), new("Эфир", accessPoints), new("Каналы", channels),
            new("Сигнал", signal), new("Устройства", devices), new("Настройки", settings)];
        _selectedNavigation = Navigation[1];
    }

    public IReadOnlyList<NavigationItem> Navigation { get; }
    [ObservableProperty]
    [NotifyPropertyChangedFor(nameof(CurrentPage))]
    private NavigationItem? _selectedNavigation;
    public ViewModelBase CurrentPage => (SelectedNavigation ?? Navigation[1]).Page;

    [RelayCommand]
    private Task InitializeAsync() => _accessPoints.InitializeAsync();
    public void Stop() => _accessPoints.Stop();
}
