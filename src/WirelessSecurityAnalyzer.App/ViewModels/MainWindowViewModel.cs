using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;

namespace WirelessSecurityAnalyzer.App.ViewModels;

public sealed record NavigationItem(string Title, ViewModelBase Page);

public sealed partial class MainWindowViewModel : ViewModelBase
{
    private readonly AccessPointsViewModel _accessPoints;
    private readonly SignalViewModel _signal;
    private readonly ChannelsViewModel _channels;
    private readonly DevicesViewModel _devices;
    public MainWindowViewModel(DashboardViewModel dashboard, AccessPointsViewModel accessPoints,
        ChannelsViewModel channels, SignalViewModel signal, DevicesViewModel devices, SettingsViewModel settings)
    {
        _accessPoints = accessPoints;
        _signal = signal;
        _channels = channels;
        _devices = devices;
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
    private Task InitializeAsync() => Task.WhenAll(_accessPoints.InitializeAsync(), _devices.InitializeAsync());
    public void Stop()
    {
        _accessPoints.Stop();
        _signal.Stop();
        _channels.Stop();
        _devices.Stop();
    }

    public async Task StopAsync()
    {
        Stop();
        await Task.WhenAll(_accessPoints.StopAsync(), _signal.StopAsync(), _channels.StopAsync(), _devices.StopAsync(),
            InitializeCommand.ExecutionTask ?? Task.CompletedTask);
    }
}
