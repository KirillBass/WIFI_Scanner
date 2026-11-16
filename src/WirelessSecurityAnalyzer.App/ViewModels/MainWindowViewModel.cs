using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;
using WirelessSecurityAnalyzer.Core.Interfaces;

namespace WirelessSecurityAnalyzer.App.ViewModels;

public sealed record NavigationItem(string Title, ViewModelBase Page);

public sealed partial class MainWindowViewModel : ViewModelBase
{
    private readonly AccessPointsViewModel _accessPoints;
    private readonly SignalViewModel _signal;
    private readonly ChannelsViewModel _channels;
    private readonly DevicesViewModel _devices;
    private readonly IWifiConnectionService? _connections;
    private readonly NetworkAuditViewModel? _audit;
    private readonly DashboardViewModel _dashboard;
    public AccessPointsViewModel AccessPoints => _accessPoints;
    public NetworkSessionViewModel? Session { get; }
    public MainWindowViewModel(DashboardViewModel dashboard, AccessPointsViewModel accessPoints,
        ChannelsViewModel channels, SignalViewModel signal, DevicesViewModel devices, SettingsViewModel settings,
        NetworkAuditViewModel? audit = null, NetworkSessionViewModel? session = null, IWifiConnectionService? connections = null)
    {
        _accessPoints = accessPoints; _dashboard = dashboard;
        _signal = signal;
        _channels = channels;
        _devices = devices;
        _audit = audit; Session = session; _connections = connections;
        var navigation = new List<NavigationItem> { new("Главная", dashboard), new("Эфир", accessPoints), new("Каналы", channels),
            new("Сигнал", signal), new("Устройства", devices) };
        if (audit is not null) navigation.Add(new("Сетевой аудит", audit));
        navigation.Add(new("Настройки", settings));
        Navigation = navigation.AsReadOnly();
        _selectedNavigation = Navigation[0];
        dashboard.AttachWorkflow(devices, audit, session);
        dashboard.NavigationRequested += Navigate;
        if (audit is not null) { audit.NavigationRequested += Navigate; audit.PropertyChanged += OnActivityChanged; }
        devices.PropertyChanged += OnActivityChanged;
        accessPoints.PropertyChanged += OnActivityChanged;
        signal.PropertyChanged += OnActivityChanged;
        if (session is not null) session.PropertyChanged += OnActivityChanged;
    }

    public IReadOnlyList<NavigationItem> Navigation { get; }
    [ObservableProperty]
    [NotifyPropertyChangedFor(nameof(CurrentPage))]
    private NavigationItem? _selectedNavigation;
    public ViewModelBase CurrentPage => (SelectedNavigation ?? Navigation[0]).Page;
    public string ActivitySummary => (_audit?.IsAuditing == true ? _audit.CompactStatus + " · " :
        _devices.IsBusy ? "Поиск устройств · " : _devices.IsMonitoring ? "Мониторинг устройств · " :
        _accessPoints.IsBusy ? "Сканирование эфира · " : _signal.IsMonitoring ? "Мониторинг сигнала · " : "") + (Session?.Summary ?? "Выберите сетевой интерфейс");
    [RelayCommand]
    private void Navigate(string page)
    {
        if (Navigation.FirstOrDefault(n => n.Title == page) is { } target) SelectedNavigation = target;
    }
    private void OnActivityChanged(object? sender, System.ComponentModel.PropertyChangedEventArgs e) => OnPropertyChanged(nameof(ActivitySummary));
    public void OpenNetworkAudit()
    {
        Session?.Refresh();
        if (_audit is not null) SelectedNavigation = Navigation.First(n => ReferenceEquals(n.Page, _audit));
    }

    partial void OnSelectedNavigationChanged(NavigationItem? value)
    {
        // Keep the default page selected when the tab strip receives an empty selection.
        if (value is null) SelectedNavigation = Navigation[0];
    }

    [RelayCommand]
    private async Task InitializeAsync()
    {
        await Task.WhenAll(_accessPoints.InitializeAsync(), _devices.InitializeAsync());
        if (_connections is not null) await _connections.InitializeAsync();
    }
    public void Stop()
    {
        _dashboard.NavigationRequested -= Navigate; _dashboard.Dispose();
        _devices.PropertyChanged -= OnActivityChanged; _accessPoints.PropertyChanged -= OnActivityChanged;
        _signal.PropertyChanged -= OnActivityChanged;
        if (Session is not null) Session.PropertyChanged -= OnActivityChanged;
        if (_audit is not null) { _audit.NavigationRequested -= Navigate; _audit.PropertyChanged -= OnActivityChanged; }
        _accessPoints.Stop();
        _signal.Stop();
        _channels.Stop();
        _devices.Stop();
        _audit?.Dispose();
    }

    public async Task StopAsync()
    {
        Stop();
        await Task.WhenAll(_accessPoints.StopAsync(), _signal.StopAsync(), _channels.StopAsync(), _devices.StopAsync(),
            _connections?.StopAsync() ?? Task.CompletedTask,
            _audit?.StopAsync() ?? Task.CompletedTask,
            InitializeCommand.ExecutionTask ?? Task.CompletedTask);
    }
}
