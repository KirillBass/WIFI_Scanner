using System.Collections.ObjectModel;
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

    public DevicesViewModel(ILocalNetworkService networks, IDeviceMonitorService monitor, DeviceDiscoveryOptions options, ILogger logger)
    {
        _networks = networks; _monitor = monitor; _options = options; _logger = logger;
        _snapshot = monitor.Current;
        _monitor.Updated += OnUpdated;
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
    public string LocalIpText => SelectedNetwork?.LocalIpv4.ToString() ?? "—";
    public string SubnetText => SelectedNetwork is { } n ? $"{n.NetworkAddress}/{n.PrefixLength}" : "—";
    public string GatewayText => SelectedNetwork?.Gateway?.ToString() ?? "—";
    public string MaskText => SelectedNetwork?.SubnetMask.ToString() ?? "—";
    public bool CanConfigure => !_stopped && !IsLoading && !IsBusy && !IsMonitoring;
    public bool CanDiscover => CanConfigure && SelectedNetwork is not null && _sweepAllowed;
    public bool CanStop => !_stopped && (IsBusy || IsMonitoring || IsResolvingIdentities);

    [ObservableProperty] private LocalNetworkInfo? _selectedNetwork;
    [ObservableProperty] private string _searchText = string.Empty;
    [ObservableProperty] private int _selectedStateIndex;
    [ObservableProperty] private int _selectedSortIndex;
    [ObservableProperty] private int _selectedInterval = 30;
    [ObservableProperty, NotifyPropertyChangedFor(nameof(CanConfigure)), NotifyCanExecuteChangedFor(nameof(ScanCommand), nameof(StartMonitoringCommand), nameof(RefreshInterfacesCommand))]
    private bool _isLoading;
    [ObservableProperty, NotifyPropertyChangedFor(nameof(CanConfigure)), NotifyCanExecuteChangedFor(nameof(ScanCommand), nameof(StartMonitoringCommand), nameof(StopMonitoringCommand), nameof(RefreshInterfacesCommand))]
    private bool _isBusy;
    [ObservableProperty, NotifyPropertyChangedFor(nameof(CanConfigure)), NotifyCanExecuteChangedFor(nameof(ScanCommand), nameof(StartMonitoringCommand), nameof(StopMonitoringCommand), nameof(RefreshInterfacesCommand))]
    private bool _isMonitoring;
    [ObservableProperty, NotifyPropertyChangedFor(nameof(CanStop)), NotifyCanExecuteChangedFor(nameof(StopMonitoringCommand))]
    private bool _isResolvingIdentities;
    [ObservableProperty] private string _statusText = "Определение локальной IPv4-сети…";
    [ObservableProperty] private string _errorMessage = string.Empty;
    [ObservableProperty] private bool _hasError;
    public bool HasWarning => !string.IsNullOrWhiteSpace(WarningText);
    [ObservableProperty, NotifyPropertyChangedFor(nameof(HasWarning))] private string _warningText = string.Empty;
    [ObservableProperty] private string _lastScanText = "Discovery ещё не выполнялся";
    [ObservableProperty] private double _progressPercent;
    [ObservableProperty] private string _progressText = string.Empty;

    public Task InitializeAsync() => RefreshInterfacesCommand.ExecuteAsync(null);

    partial void OnSearchTextChanged(string value) => ApplyFilter();
    partial void OnSelectedStateIndexChanged(int value) => ApplyFilter();
    partial void OnSelectedSortIndexChanged(int value) => ApplyFilter();
    partial void OnSelectedNetworkChanged(LocalNetworkInfo? value)
    {
        _shownDevices = null; _rows.Clear(); Devices.Clear();
        foreach (var name in new[] { nameof(InterfaceText), nameof(LocalIpText), nameof(SubnetText), nameof(GatewayText), nameof(MaskText) }) OnPropertyChanged(name);
        _sweepAllowed = false;
        HasError = false; ErrorMessage = string.Empty; WarningText = string.Empty;
        StatusText = value is null ? "Активный локальный IPv4-интерфейс не найден." : "Нажмите «Сканировать», чтобы обнаружить устройства локальной сети.";
        LastScanText = "Discovery ещё не выполнялся";
        if (value is not null)
            try { value.Subnet.EnsureSweepAllowed(_options.MaxAutoHostCount); _sweepAllowed = true; }
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
    private async Task ScanAsync()
    {
        if (SelectedNetwork is not { } network || _stopped) return;
        IsBusy = true; HasError = false;
        Exception? failure = null;
        try { await _monitor.DiscoverOnceAsync(network, _options, _lifetime.Token).ConfigureAwait(false); }
        catch (OperationCanceledException) when (_lifetime.IsCancellationRequested) { }
        catch (Exception exception) { failure = exception; }
        finally { await Dispatcher.UIThread.InvokeAsync(() => { if (!_stopped) { ApplySnapshot(_monitor.Current); if (failure is not null) ShowError(failure); } }); }
    }

    [RelayCommand(CanExecute = nameof(CanDiscover))]
    private async Task StartMonitoringAsync()
    {
        if (SelectedNetwork is not { } network || _stopped) return;
        IsBusy = true; HasError = false;
        Exception? failure = null;
        try { await _monitor.StartAsync(network, _options, TimeSpan.FromSeconds(SelectedInterval), _lifetime.Token).ConfigureAwait(false); }
        catch (OperationCanceledException) when (_lifetime.IsCancellationRequested) { }
        catch (Exception exception) { failure = exception; }
        finally { await Dispatcher.UIThread.InvokeAsync(() => { if (!_stopped) { ApplySnapshot(_monitor.Current); if (failure is not null) ShowError(failure); } }); }
    }

    [RelayCommand(CanExecute = nameof(CanStop))]
    private async Task StopMonitoringAsync()
    {
        await _monitor.StopAsync().ConfigureAwait(false);
        await Dispatcher.UIThread.InvokeAsync(() =>
        {
            if (_stopped) return;
            ApplySnapshot(_monitor.Current);
            if (!HasError) StatusText = "Операция остановлена. Последние успешные результаты сохранены.";
        });
    }

    private void OnUpdated(object? sender, DeviceMonitorSnapshot snapshot) =>
        Dispatcher.UIThread.Post(() => { if (!_stopped) ApplySnapshot(snapshot); });

    private void ApplySnapshot(DeviceMonitorSnapshot snapshot)
    {
        if (snapshot.Version < _snapshot.Version) return;
        _snapshot = snapshot;
        if (SelectedNetwork is { } selected && snapshot.Network is { } network && selected.HasSameContext(network)) RenderSnapshot();
        else { IsBusy = snapshot.IsDiscovering; IsMonitoring = snapshot.IsMonitoring; IsResolvingIdentities = snapshot.IsResolvingIdentities; }
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
            foreach (var device in _snapshot.Devices)
            {
                var row = _rows.FirstOrDefault(r => !target.Contains(r) && device.MacAddress is not null && Equals(r.Device.MacAddress, device.MacAddress));
                row ??= _rows.FirstOrDefault(r => !target.Contains(r) && r.Device.IpAddress.Equals(device.IpAddress) &&
                    (device.MacAddress is null || r.Device.MacAddress is null || Equals(r.Device.MacAddress, device.MacAddress)));
                if (row is null) row = new DeviceRowViewModel(device); else row.Device = device;
                target.Add(row);
            }
            _rows.Clear(); _rows.AddRange(target); _shownDevices = _snapshot.Devices;
            ApplyFilter(); NotifyCounts();
        }
        LastScanText = _snapshot.LastCompletedAt is { } completed ? $"Последний discovery: {completed.ToLocalTime():dd.MM HH:mm:ss}" : "Discovery ещё не выполнялся";
        if (_snapshot.Progress is { } p)
        {
            ProgressPercent = p.Total == 0 ? 0 : p.Probed * 100d / p.Total;
            var stage = p.Stage switch { DeviceDiscoveryStage.Probe => "Проверка адресов", DeviceDiscoveryStage.NeighborMerge => "Объединение соседей", DeviceDiscoveryStage.HostnameResolution => "Определение имён", _ => "Завершение" };
            ProgressText = $"{stage}: {p.Probed} / {p.Total} · подтверждено: {p.Found}";
        }
        StatusText = HasError ? "Операция не выполнена. Последние успешные результаты сохранены." : IsBusy ? "Обнаружение устройств локальной сети…" :
            IsResolvingIdentities ? $"Найдено устройств: {KnownCount} · имена и производители определяются асинхронно…" :
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
        var target = sorted.ToArray();
        var visible = target.ToHashSet();
        for (var i = Devices.Count - 1; i >= 0; i--) if (!visible.Contains(Devices[i])) Devices.RemoveAt(i);
        for (var i = 0; i < target.Length; i++)
        {
            if (i < Devices.Count && ReferenceEquals(Devices[i], target[i])) continue;
            var old = Devices.IndexOf(target[i]);
            if (old >= 0) Devices.Move(old, i); else Devices.Insert(i, target[i]);
        }
        OnPropertyChanged(nameof(IsEmpty)); OnPropertyChanged(nameof(EmptyText));
    }

    private void NotifyCounts()
    {
        foreach (var name in new[] { nameof(KnownCount), nameof(OnlineCount), nameof(UnknownCount), nameof(OfflineCount), nameof(IsEmpty), nameof(EmptyText) }) OnPropertyChanged(name);
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
        NetworkDiscoveryError.SubnetTooLarge => "Автоматический полный scan отключён: подсеть содержит слишком много адресов. Максимум — 1024 адреса.",
        NetworkDiscoveryError.UnsupportedSubnet => "Автоматический обход /31 и /32 пока не поддерживается.",
        NetworkDiscoveryError.NeighborTableFailed => "Не удалось прочитать таблицу соседей Windows. Последние результаты сохранены.",
        NetworkDiscoveryError.ProbeFailed => "Не удалось выполнить ICMP-проверки. Проверьте подключение и разрешения Windows.",
        NetworkDiscoveryError.Busy => "Обнаружение уже выполняется. Дождитесь завершения или нажмите «Остановить».",
        _ => "Не удалось обнаружить устройства. Подробности сохранены в локальном журнале."
    };

    public void Stop()
    {
        if (_stopped) return;
        _stopped = true; _monitor.Updated -= OnUpdated; _lifetime.Cancel();
    }

    public async Task StopAsync()
    {
        Stop();
        await _monitor.StopAsync();
        await Task.WhenAll(ScanCommand.ExecutionTask ?? Task.CompletedTask, StartMonitoringCommand.ExecutionTask ?? Task.CompletedTask,
            StopMonitoringCommand.ExecutionTask ?? Task.CompletedTask, RefreshInterfacesCommand.ExecutionTask ?? Task.CompletedTask);
    }
}
