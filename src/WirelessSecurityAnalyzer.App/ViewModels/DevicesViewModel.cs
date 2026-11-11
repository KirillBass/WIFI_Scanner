using System.Collections.ObjectModel;
using System.ComponentModel;
using Avalonia.Threading;
using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;
using Serilog;
using WirelessSecurityAnalyzer.Core.Interfaces;
using WirelessSecurityAnalyzer.Core.Models;
using WirelessSecurityAnalyzer.Core.Network;

namespace WirelessSecurityAnalyzer.App.ViewModels;

public sealed partial class DevicesViewModel : ViewModelBase
{
    private readonly ILocalNetworkService _networks;
    private readonly IDeviceMonitorService _monitor;
    private readonly DeviceDiscoveryOptions _options;
    private readonly ILogger _logger;
    private readonly CancellationTokenSource _lifetime = new();
    private readonly List<DeviceRowViewModel> _rows = [];
    private DeviceMonitorSnapshot _snapshot;
    private IReadOnlyList<NetworkDevice>? _shownDevices;
    private bool _sweepAllowed;
    private bool _stopped;
    private bool _namesStopped;
    private const string NamesStoppedMessage = "Поиск имён остановлен. Найденные устройства сохранены. Для повторной попытки нажмите «Обновить имена».";
    private readonly NetworkSessionViewModel? _session;
    private Guid _sessionId;
    private bool _sessionNetworkApplied;
    private readonly object _dispatchGate = new();
    private DeviceMonitorSnapshot? _pendingSnapshot;
    private bool _updateQueued;

    public DevicesViewModel(ILocalNetworkService networks, IDeviceMonitorService monitor, DeviceDiscoveryOptions options, ILogger logger,
        NetworkSessionViewModel? session = null)
    {
        _networks = networks; _monitor = monitor; _options = options; _logger = logger;
        _snapshot = monitor.Current;
        _monitor.Updated += OnUpdated;
        _session = session;
        if (_session is not null) { _session.PropertyChanged += OnSessionChanged; ApplySession(); }
    }

    public ObservableCollection<LocalNetworkInfo> Networks { get; } = [];
    public ObservableCollection<DeviceRowViewModel> Devices { get; } = [];
    public IReadOnlyList<string> StateFilters { get; } = ["Все", "Online · В сети", "Unknown · Неизвестно", "Offline · Недоступно"];
    public IReadOnlyList<string> SortOptions { get; } = ["IP ↑", "Ping ↑", "Последний раз ↓"];
    public IReadOnlyList<int> Intervals { get; } = [10, 30, 60, 120];
    public int KnownCount => _rows.Count;
    public int OnlineCount => _rows.Count(r => r.Device.State == DeviceState.Online);
    public int UnknownCount => _rows.Count(r => r.Device.State == DeviceState.Unknown);
    public int OfflineCount => _rows.Count(r => r.Device.State == DeviceState.Offline);
    public bool IsEmpty => Devices.Count == 0;
    public string EmptyText => KnownCount > 0 ? "Нет устройств, соответствующих фильтрам." : "Устройства пока не обнаружены.";
    public string InterfaceText => SelectedNetwork?.InterfaceDescription ?? "Активный локальный IPv4-интерфейс не найден";
    public string LocalIpText => SelectedNetwork?.LocalIpv4.ToString() ?? "-";
    public string SubnetText => SelectedNetwork is { } n ? $"{n.NetworkAddress}/{n.PrefixLength}" : "-";
    public string GatewayText => SelectedNetwork?.Gateway?.ToString() ?? "-";
    public string MaskText => SelectedNetwork?.SubnetMask.ToString() ?? "-";
    public bool CanConfigure => !_stopped && !IsLoading && !IsBusy && !IsMonitoring &&
        !(_session?.Current.State is WifiConnectionState.Connecting or WifiConnectionState.Authenticating or
            WifiConnectionState.Connected or WifiConnectionState.ObtainingAddress or WifiConnectionState.Disconnecting);
    public bool CanDiscover => CanConfigure && SelectedNetwork is not null && _sweepAllowed;
    public bool CanRefreshNames => CanConfigure && !IsResolvingIdentities && OnlineCount > 0 &&
        SelectedNetwork is { } selected && _snapshot.Network?.HasSameContext(selected) == true;
    public bool CanStop => !_stopped && (IsBusy || IsMonitoring || IsResolvingIdentities);

    [ObservableProperty] private LocalNetworkInfo? _selectedNetwork;
    [ObservableProperty] private string _searchText = string.Empty;
    [ObservableProperty] private int _selectedStateIndex;
    [ObservableProperty] private int _selectedSortIndex;
    [ObservableProperty] private int _selectedInterval = 30;
    [ObservableProperty, NotifyPropertyChangedFor(nameof(CanConfigure)), NotifyCanExecuteChangedFor(nameof(ScanCommand), nameof(StartMonitoringCommand), nameof(RefreshInterfacesCommand), nameof(RefreshNamesCommand))]
    private bool _isLoading;
    [ObservableProperty, NotifyPropertyChangedFor(nameof(CanConfigure)), NotifyCanExecuteChangedFor(nameof(ScanCommand), nameof(StartMonitoringCommand), nameof(StopMonitoringCommand), nameof(RefreshInterfacesCommand), nameof(RefreshNamesCommand))]
    private bool _isBusy;
    [ObservableProperty, NotifyPropertyChangedFor(nameof(CanConfigure)), NotifyCanExecuteChangedFor(nameof(ScanCommand), nameof(StartMonitoringCommand), nameof(StopMonitoringCommand), nameof(RefreshInterfacesCommand), nameof(RefreshNamesCommand))]
    private bool _isMonitoring;
    [ObservableProperty, NotifyPropertyChangedFor(nameof(CanStop)), NotifyCanExecuteChangedFor(nameof(StopMonitoringCommand), nameof(RefreshNamesCommand))]
    private bool _isResolvingIdentities;
    [ObservableProperty] private string _statusText = "Определение локальной IPv4-сети…";
    [ObservableProperty] private string _errorMessage = string.Empty;
    [ObservableProperty] private bool _hasError;
    public bool HasWarning => !string.IsNullOrWhiteSpace(WarningText);
    [ObservableProperty, NotifyPropertyChangedFor(nameof(HasWarning))] private string _warningText = string.Empty;
    [ObservableProperty] private string _lastScanText = "Discovery ещё не выполнялся";
    [ObservableProperty] private bool _hasProgress;
    [ObservableProperty] private double _progressPercent;
    [ObservableProperty] private string _progressText = string.Empty;

    public Task InitializeAsync() => RefreshInterfacesCommand.ExecuteAsync(null);

    public void UseSessionNetwork(LocalNetworkInfo network)
    {
        var entry = Networks.FirstOrDefault(n => n.HasSameContext(network));
        if (entry is null) { Networks.Add(network); entry = network; }
        if (SelectedNetwork?.HasSameContext(entry) != true) SelectedNetwork = entry;
    }
    private void OnSessionChanged(object? sender, PropertyChangedEventArgs e)
    { if (e.PropertyName == nameof(NetworkSessionViewModel.Current)) ApplySession(); }
    private void ApplySession()
    {
        if (_session is null || _stopped) return;
        var session = _session.Current;
        if (_sessionId != session.SessionId)
        {
            _sessionId = session.SessionId; _sessionNetworkApplied = false;
            _shownDevices = null; _rows.Clear(); Devices.Clear(); SelectedNetwork = null;
            NotifyCounts();
        }
        if (!_sessionNetworkApplied && session.IsReadyForAudit && session.Network is { } network)
        { UseSessionNetwork(network); _sessionNetworkApplied = true; }
        OnPropertyChanged(nameof(CanConfigure));
        ScanCommand.NotifyCanExecuteChanged(); StartMonitoringCommand.NotifyCanExecuteChanged();
        RefreshInterfacesCommand.NotifyCanExecuteChanged(); StopMonitoringCommand.NotifyCanExecuteChanged(); RefreshNamesCommand.NotifyCanExecuteChanged();
    }

    partial void OnSearchTextChanged(string value) => ApplyFilter();
    partial void OnSelectedStateIndexChanged(int value) => ApplyFilter();
    partial void OnSelectedSortIndexChanged(int value) => ApplyFilter();
    partial void OnSelectedNetworkChanged(LocalNetworkInfo? value)
    {
        _namesStopped = false;
        _shownDevices = null; _rows.Clear(); Devices.Clear();
        foreach (var name in new[] { nameof(InterfaceText), nameof(LocalIpText), nameof(SubnetText), nameof(GatewayText), nameof(MaskText) }) OnPropertyChanged(name);
        _sweepAllowed = false;
        HasError = false; ErrorMessage = string.Empty; WarningText = string.Empty;
        StatusText = value is null ? "Активный локальный IPv4-интерфейс не найден." : "Нажмите «Сканировать», чтобы обнаружить устройства локальной сети.";
        LastScanText = "Discovery ещё не выполнялся";
        HasProgress = false; ProgressText = string.Empty; ProgressPercent = 0;
        if (value is not null)
            try { value.Subnet.EnsureSweepAllowed(); _sweepAllowed = true; }
            catch (NetworkDiscoveryException exception) { WarningText = GetMessage(exception); }
        NotifyCounts();
        ScanCommand.NotifyCanExecuteChanged(); StartMonitoringCommand.NotifyCanExecuteChanged();
        if (_snapshot.Network is { } network && value is not null && network.HasSameContext(value)) RenderSnapshot();
    }

    [RelayCommand(CanExecute = nameof(CanConfigure))]
    private async Task RefreshInterfacesAsync()
    {
        IsLoading = true;
        try
        {
            var networks = await _networks.GetNetworksAsync(_lifetime.Token).ConfigureAwait(false);
            await Dispatcher.UIThread.InvokeAsync(() =>
            {
                if (_stopped) return;
                var previous = SelectedNetwork;
                Networks.Clear();
                foreach (var network in networks) Networks.Add(network);
                SelectedNetwork = networks.FirstOrDefault(n => previous is not null && n.HasSameContext(previous)) ?? networks.FirstOrDefault();
                if (SelectedNetwork is null) StatusText = "Активный локальный IPv4-интерфейс не найден.";
                else _logger.Information("Available local IPv4 contexts {Count}; selected {InterfaceId}", networks.Count, SelectedNetwork.InterfaceId);
            });
        }
        catch (OperationCanceledException) when (_lifetime.IsCancellationRequested) { }
        catch (Exception exception)
        {
            _logger.Warning(exception, "Local network detection failed");
            await Dispatcher.UIThread.InvokeAsync(() => { if (!_stopped) ShowError(exception); });
        }
        finally { await Dispatcher.UIThread.InvokeAsync(() => IsLoading = false); }
    }

    [RelayCommand(CanExecute = nameof(CanDiscover))]
    private Task ScanAsync() => RunDiscoveryAsync(network => _monitor.DiscoverOnceAsync(network, _options, _lifetime.Token));

    [RelayCommand(CanExecute = nameof(CanRefreshNames))]
    private Task RefreshNamesAsync() => RunDiscoveryAsync(network => _monitor.RefreshIdentitiesAsync(network, _lifetime.Token));

    [RelayCommand(CanExecute = nameof(CanDiscover))]
    private Task StartMonitoringAsync() => RunDiscoveryAsync(network =>
        _monitor.StartAsync(network, _options, TimeSpan.FromSeconds(SelectedInterval), _lifetime.Token));

    private async Task RunDiscoveryAsync(Func<LocalNetworkInfo, Task> operation)
    {
        if (SelectedNetwork is not { } network || _stopped) return;
        _namesStopped = false;
        IsBusy = true; HasError = false;
        Exception? failure = null;
        try { await operation(network).ConfigureAwait(false); }
        catch (OperationCanceledException) when (_lifetime.IsCancellationRequested) { }
        catch (Exception exception) { failure = exception; }
        finally { await Dispatcher.UIThread.InvokeAsync(() => { if (!_stopped) { ApplySnapshot(_monitor.Current); if (failure is not null) ShowError(failure); } }); }
    }

    [RelayCommand(CanExecute = nameof(CanStop))]
    private async Task StopMonitoringAsync()
    {
        var namesWerePending = IsResolvingIdentities;
        _namesStopped = namesWerePending;
        await _monitor.StopAsync().ConfigureAwait(false);
        await Dispatcher.UIThread.InvokeAsync(() =>
        {
            if (_stopped) return;
            ApplySnapshot(_monitor.Current);
            if (!HasError && _snapshot.Progress?.Stage != DeviceDiscoveryStage.Cancelled) StatusText = namesWerePending
                ? NamesStoppedMessage
                : "Операция остановлена. Последние успешные результаты сохранены.";
        });
    }

    private void OnUpdated(object? sender, DeviceMonitorSnapshot snapshot)
    {
        lock (_dispatchGate)
        {
            if (_pendingSnapshot is null || snapshot.Version > _pendingSnapshot.Version) _pendingSnapshot = snapshot;
            if (_updateQueued) return;
            _updateQueued = true;
        }
        Dispatcher.UIThread.Post(() =>
        {
            DeviceMonitorSnapshot? latest;
            lock (_dispatchGate) { latest = _pendingSnapshot; _pendingSnapshot = null; _updateQueued = false; }
            if (!_stopped && latest is not null) ApplySnapshot(latest);
        });
    }

    private void ApplySnapshot(DeviceMonitorSnapshot snapshot)
    {
        if (snapshot.Version < _snapshot.Version) return;
        _snapshot = snapshot;
        if (SelectedNetwork is { } selected && snapshot.Network is { } network && selected.HasSameContext(network)) RenderSnapshot();
        else
        {
            IsBusy = snapshot.IsDiscovering; IsMonitoring = snapshot.IsMonitoring; IsResolvingIdentities = snapshot.IsResolvingIdentities;
            if (snapshot.Network is null)
            {
                _rows.Clear(); Devices.Clear(); _shownDevices = null; HasProgress = false;
                NotifyCounts();
            }
        }
    }

    private void RenderSnapshot()
    {
        IsBusy = _snapshot.IsDiscovering; IsMonitoring = _snapshot.IsMonitoring; IsResolvingIdentities = _snapshot.IsResolvingIdentities;
        HasError = _snapshot.Error is not null;
        ErrorMessage = _snapshot.Error is { } error ? GetMessage(error) : string.Empty;
        if (_sweepAllowed) WarningText = _snapshot.Warning ?? string.Empty;
        if (!ReferenceEquals(_shownDevices, _snapshot.Devices))
        {
            var target = new List<DeviceRowViewModel>();
            var used = new HashSet<DeviceRowViewModel>();
            var byIp = _rows.GroupBy(r => r.Device.IpAddress).ToDictionary(g => g.Key, g => g.First());
            var byMac = _rows.Where(r => r.Device.MacAddress is not null).GroupBy(r => r.Device.MacAddress!)
                .ToDictionary(g => g.Key, g => g.First());
            foreach (var device in _snapshot.Devices)
            {
                byIp.TryGetValue(device.IpAddress, out var row);
                if (row is not null && used.Contains(row)) row = null;
                if (row is null && device.MacAddress is not null && byMac.TryGetValue(device.MacAddress, out var macRow) && !used.Contains(macRow)) row = macRow;
                if (row is null) row = new DeviceRowViewModel(device, SelectedNetwork?.Name);
                else if (row.Device != device) row.Device = device;
                used.Add(row);
                target.Add(row);
            }
            _rows.Clear(); _rows.AddRange(target); _shownDevices = _snapshot.Devices;
            ApplyFilter(); NotifyCounts();
        }
        LastScanText = _snapshot.LastCompletedAt is { } completed ? $"Последний discovery: {completed.ToLocalTime():dd.MM HH:mm:ss}" : "Discovery ещё не выполнялся";
        HasProgress = _snapshot.Progress is not null;
        if (_snapshot.Progress is { } p)
        {
            ProgressPercent = p.Total == 0 ? 0 : p.Probed * 100d / p.Total;
            var stage = p.Stage switch
            {
                DeviceDiscoveryStage.Priority => "Приоритетные адреса", DeviceDiscoveryStage.Subnet => "Обход подсети",
                DeviceDiscoveryStage.Probe => "Проверка адресов", DeviceDiscoveryStage.NeighborMerge => "Объединение соседей",
                DeviceDiscoveryStage.HostnameResolution => "Определение имён", DeviceDiscoveryStage.Cancelled => "Остановлено, частичный результат",
                DeviceDiscoveryStage.Error => "Ошибка, частичный результат", _ => "Сканирование завершено"
            };
            ProgressText = $"{stage}: {p.Probed:N0} / {p.Total:N0} ({ProgressPercent:F2}%) · найдено: {p.Found} · активных проверок: {p.Active} · время: {(int)p.Elapsed.TotalHours:00}:{p.Elapsed.Minutes:00}:{p.Elapsed.Seconds:00}";
        }
        StatusText = HasError ? "Операция не выполнена. Найденные результаты сохранены." :
            _snapshot.Progress is { Stage: DeviceDiscoveryStage.Cancelled } partial ?
                $"Сканирование остановлено. Проверено: {partial.Probed:N0} из {partial.Total:N0}. Найдено: {partial.Found}. Результаты сохранены; непроверенные адреса не считаются Offline." : IsBusy ? "Обнаружение устройств локальной сети…" :
            IsResolvingIdentities ? $"Найдено устройств: {KnownCount} · имена и производители определяются асинхронно…" :
            _namesStopped ? NamesStoppedMessage :
            IsMonitoring ? "● Мониторинг активен · следующий цикл после завершения интервала" :
            _snapshot.LastCompletedAt is null ? "Нажмите «Сканировать», чтобы обнаружить устройства локальной сети." :
            _rows.All(r => r.Device.IsLocalMachine) ? "Другие активные устройства не обнаружены. Возможны Client Isolation, guest network или фильтрация ICMP." : $"Известно устройств: {KnownCount} · Online: {OnlineCount}";
    }

    private void ApplyFilter()
    {
        var query = SearchText.Trim();
        var state = SelectedStateIndex switch { 1 => DeviceState.Online, 2 => DeviceState.Unknown, 3 => DeviceState.Offline, _ => (DeviceState?)null };
        var filtered = _rows.Where(r => (state is null || r.Device.State == state) &&
            (query.Length == 0 || r.Ip.Contains(query, StringComparison.OrdinalIgnoreCase) || r.Mac.Contains(query, StringComparison.OrdinalIgnoreCase) ||
             r.Mac.Replace(":", "").Contains(query.Replace(":", "").Replace("-", ""), StringComparison.OrdinalIgnoreCase) || r.Hostname.Contains(query, StringComparison.OrdinalIgnoreCase) ||
             r.Device.DisplayName.Contains(query, StringComparison.OrdinalIgnoreCase) || r.Vendor.Contains(query, StringComparison.OrdinalIgnoreCase)));
        var sorted = SelectedSortIndex switch
        {
            1 => filtered.OrderBy(r => r.Device.Latency?.TotalMilliseconds ?? double.MaxValue).ThenBy(r => SubnetCalculator.ToUInt32(r.Device.IpAddress)),
            2 => filtered.OrderByDescending(r => r.Device.LastSeen).ThenBy(r => SubnetCalculator.ToUInt32(r.Device.IpAddress)),
            _ => filtered.OrderBy(r => SubnetCalculator.ToUInt32(r.Device.IpAddress))
        };
        SynchronizeRows(Devices, sorted.ToArray());
        OnPropertyChanged(nameof(IsEmpty)); OnPropertyChanged(nameof(EmptyText));
    }

    private void NotifyCounts()
    {
        foreach (var name in new[] { nameof(KnownCount), nameof(OnlineCount), nameof(UnknownCount), nameof(OfflineCount), nameof(IsEmpty), nameof(EmptyText) }) OnPropertyChanged(name);
        RefreshNamesCommand.NotifyCanExecuteChanged();
    }

    private void ShowError(Exception exception)
    {
        _logger.Warning(exception, "Local network UI operation failed");
        HasError = true;
        ErrorMessage = exception is NetworkDiscoveryException network ? GetMessage(network) : "Не удалось обнаружить устройства. Подробности сохранены в локальном журнале.";
        StatusText = "Операция не выполнена. Последние успешные результаты сохранены.";
    }

    private static string GetMessage(NetworkDiscoveryException exception) => exception.Kind switch
    {
        NetworkDiscoveryError.UnsupportedPlatform => "Обнаружение устройств доступно в Windows 10/11. Таблица соседей Windows на этой платформе недоступна.",
        NetworkDiscoveryError.NoInterface => "Активный локальный IPv4-интерфейс не найден.",
        NetworkDiscoveryError.ContextChanged => "Интерфейс или IPv4-сеть изменились. Мониторинг остановлен; обновите список интерфейсов и повторите сканирование.",
        NetworkDiscoveryError.UnsupportedSubnet => "Подсеть не содержит допустимых адресов IPv4 для обнаружения.",
        NetworkDiscoveryError.NeighborTableFailed => "Не удалось прочитать таблицу соседей Windows. Последние результаты сохранены.",
        NetworkDiscoveryError.ProbeFailed => "Не удалось выполнить ICMP-проверки. Проверьте подключение и разрешения Windows.",
        NetworkDiscoveryError.Busy => "Обнаружение уже выполняется. Дождитесь завершения или нажмите «Остановить».",
        _ => "Не удалось обнаружить устройства. Подробности сохранены в локальном журнале."
    };

    public void Stop()
    {
        if (_stopped) return;
        _stopped = true; _monitor.Updated -= OnUpdated; _lifetime.Cancel();
        if (_session is not null) _session.PropertyChanged -= OnSessionChanged;
    }

    public async Task StopAsync()
    {
        Stop();
        await _monitor.StopAsync();
        await Task.WhenAll(ScanCommand.ExecutionTask ?? Task.CompletedTask, StartMonitoringCommand.ExecutionTask ?? Task.CompletedTask,
            StopMonitoringCommand.ExecutionTask ?? Task.CompletedTask, RefreshInterfacesCommand.ExecutionTask ?? Task.CompletedTask,
            RefreshNamesCommand.ExecutionTask ?? Task.CompletedTask);
    }
}
