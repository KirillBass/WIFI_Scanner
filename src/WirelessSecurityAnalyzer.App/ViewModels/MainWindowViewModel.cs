using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;
using WirelessSecurityAnalyzer.Core.Interfaces;

namespace WirelessSecurityAnalyzer.App.ViewModels;

public sealed class NavigationItem(string title, ViewModelBase page) : ViewModelBase
{
    public string Title { get; } = title;
    public ViewModelBase Page { get; } = page;
    private bool _isAvailable = true;
    private string _unavailableReason = "";
    public bool IsAvailable { get => _isAvailable; private set => SetProperty(ref _isAvailable, value); }
    public string UnavailableReason { get => _unavailableReason; private set => SetProperty(ref _unavailableReason, value); }
    public void SetAvailability(bool available, string reason)
    { IsAvailable = available; UnavailableReason = available ? "" : reason; }
}

public sealed partial class MainWindowViewModel : ViewModelBase
{
    private readonly AccessPointsViewModel _accessPoints;
    private readonly SignalViewModel _signal;
    private readonly ChannelsViewModel _channels;
    private readonly DevicesViewModel _devices;
    private readonly IWifiConnectionService? _connections;
    private readonly NetworkAuditViewModel? _audit;
    private readonly NavigationItem _defaultNavigation;
    private NavigationItem? _lastAvailableNavigation;
    private Guid _wifiSessionId;
    private long _wifiSnapshotFloor;
    public AccessPointsViewModel AccessPoints => _accessPoints;
    public NetworkSessionViewModel? Session { get; }
    public MainWindowViewModel(AccessPointsViewModel accessPoints,
        ChannelsViewModel channels, SignalViewModel signal, DevicesViewModel devices, SettingsViewModel settings,
        NetworkAuditViewModel? audit = null, NetworkSessionViewModel? session = null, IWifiConnectionService? connections = null)
    {
        _accessPoints = accessPoints;
        _signal = signal;
        _channels = channels;
        _devices = devices;
        _audit = audit; Session = session; _connections = connections;
        var navigation = new List<NavigationItem> { new("Эфир", accessPoints), new("Каналы", channels),
            new("Сигнал", signal), new("Устройства", devices) };
        if (audit is not null) navigation.Add(new("Сетевой аудит", audit));
        navigation.Add(new("Настройки", settings));
        Navigation = navigation.AsReadOnly();
        _wifiSessionId = Session?.Current.SessionId ?? Guid.Empty;
        UpdateAvailability();
        _defaultNavigation = Navigation.FirstOrDefault(n => n.Title == settings.StartupPage && n.IsAvailable) ?? DeviceNavigation;
        _lastAvailableNavigation = _defaultNavigation;
        _selectedNavigation = _defaultNavigation;
        if (audit is not null) audit.PropertyChanged += OnActivityChanged;
        devices.PropertyChanged += OnActivityChanged;
        accessPoints.PropertyChanged += OnActivityChanged;
        signal.PropertyChanged += OnActivityChanged;
        if (session is not null) session.PropertyChanged += OnActivityChanged;
    }

    public IReadOnlyList<NavigationItem> Navigation { get; }
    [ObservableProperty]
    [NotifyPropertyChangedFor(nameof(CurrentPage))]
    private NavigationItem? _selectedNavigation;
    public ViewModelBase CurrentPage => (SelectedNavigation ?? _defaultNavigation).Page;
    public string ActivitySummary => (_audit?.IsAuditing == true ? _audit.CompactStatus + " · " :
        _devices.IsBusy ? "Поиск устройств · " : _devices.IsMonitoring ? "Мониторинг устройств · " :
        _accessPoints.IsBusy ? "Сканирование эфира · " : _signal.IsMonitoring ? "Мониторинг сигнала · " : "") + (Session?.Summary ?? "Выберите сетевой интерфейс");
    [RelayCommand]
    private void Navigate(string page)
    {
        if (Navigation.FirstOrDefault(n => n.Title == page && n.IsAvailable) is { } target) SelectedNavigation = target;
    }
    private NavigationItem DeviceNavigation => Navigation.First(n => ReferenceEquals(n.Page, _devices));
    private void UpdateAvailability()
    {
        var freshWifi = _accessPoints.SnapshotVersion > _wifiSnapshotFloor;
        foreach (var item in Navigation)
            switch (item.Title)
            {
                case "Каналы": item.SetAvailability(freshWifi && _accessPoints.HasGraphData,
                    "Сначала выполните сканирование Wi-Fi во вкладке «Эфир»."); break;
                case "Сигнал": item.SetAvailability(freshWifi && _signal.HasAccessPoints,
                    "Сначала найдите точки доступа во вкладке «Эфир»."); break;
                case "Сетевой аудит": item.SetAvailability(Session?.IsReady == true && _devices.CanOpenAudit,
                    "Сначала выберите интерфейс и выполните поиск устройств во вкладке «Устройства»."); break;
            }
    }
    private void OnActivityChanged(object? sender, System.ComponentModel.PropertyChangedEventArgs e)
    {
        if (Session is not null && Session.Current.SessionId != _wifiSessionId)
        {
            _wifiSessionId = Session.Current.SessionId;
            _wifiSnapshotFloor = _accessPoints.SnapshotVersion;
        }
        UpdateAvailability();
        if (SelectedNavigation is { IsAvailable: false }) SelectedNavigation = DeviceNavigation;
        OnPropertyChanged(nameof(ActivitySummary));
    }
    public void OpenNetworkAudit()
    {
        Session?.Refresh();
        if (_audit is not null && Navigation.First(n => ReferenceEquals(n.Page, _audit)) is { IsAvailable: true } target) SelectedNavigation = target;
    }

    partial void OnSelectedNavigationChanged(NavigationItem? value)
    {
        if (value is null || !value.IsAvailable)
        {
            SelectedNavigation = _lastAvailableNavigation is { IsAvailable: true } previous ? previous : DeviceNavigation;
            return;
        }
        _lastAvailableNavigation = value;
    }

    [RelayCommand]
    private async Task InitializeAsync()
    {
        await Task.WhenAll(_accessPoints.InitializeAsync(), _devices.InitializeAsync());
        if (_connections is not null) await _connections.InitializeAsync();
    }
    public void Stop()
    {
        _devices.PropertyChanged -= OnActivityChanged; _accessPoints.PropertyChanged -= OnActivityChanged;
        _signal.PropertyChanged -= OnActivityChanged;
        if (Session is not null) Session.PropertyChanged -= OnActivityChanged;
        if (_audit is not null) _audit.PropertyChanged -= OnActivityChanged;
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
