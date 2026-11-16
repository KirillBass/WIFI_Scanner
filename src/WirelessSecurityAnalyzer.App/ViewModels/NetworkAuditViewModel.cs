using System.Collections.ObjectModel;
using System.ComponentModel;
using System.Globalization;
using System.Diagnostics;
using Avalonia.Threading;
using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;
using WirelessSecurityAnalyzer.Core.Interfaces;
using WirelessSecurityAnalyzer.Core.NetworkAudit;

namespace WirelessSecurityAnalyzer.App.ViewModels;

public sealed partial class NetworkAuditViewModel : ViewModelBase, IDisposable
{
    private readonly IWifiConnectionService _connections;
    private readonly INetworkAuditService? _audit;
    private IReadOnlyList<AuditRow> _allRows = [];
    private AuditSnapshot _snapshot = AuditSnapshot.Empty;
    private long _version = -1;
    private bool _disposed;
    private readonly object _dispatchGate = new();
    private AuditSnapshot? _pendingSnapshot;
    private bool _updateQueued;
    public NetworkAuditViewModel(NetworkSessionViewModel session, DevicesViewModel devices, IWifiConnectionService connections,
        INetworkAuditService? audit = null)
    {
        Session = session; Devices = devices; _connections = connections; _audit = audit;
        Session.PropertyChanged += OnStateChanged; Devices.PropertyChanged += OnStateChanged;
        if (_audit is not null) { _audit.Updated += OnAuditUpdated; Apply(_audit.Current); }
    }
    public NetworkSessionViewModel Session { get; }
    public DevicesViewModel Devices { get; }
    public event Action<string>? NavigationRequested;
    public bool HasAudit => _snapshot.AuditId != Guid.Empty;
    public string PrimaryActionText => IsAuditing ? "Остановить" : Session.IsObtainingAddress ? "Получение IPv4…" : Session.IsReady ? "Найти серверы" : "Выбрать интерфейс";
    public string ReadinessText => IsAuditing ? "" : Session.IsObtainingAddress ? "Wi-Fi подключён. Дождитесь получения IPv4; при необходимости отмените подключение." :
        Session.IsConnecting ? "Дождитесь завершения подключения к Wi-Fi." : !Session.IsReady ? "Для аудита нужен активный IPv4-интерфейс. Выберите Ethernet или Wi-Fi в разделе «Устройства»." :
        Devices.IsMonitoring ? "Сначала остановите мониторинг в разделе «Устройства»." :
        Devices.IsBusy ? "Выполняется поиск устройств. Дождитесь завершения или остановите его в разделе «Устройства»." :
        DeviceCount == 0 ? "Поиск сначала обнаружит устройства выбранной сети, затем проверит SMB, FTP и веб-службы." :
        $"Устройств в текущей сети: {DeviceCount}. При необходимости список обновится перед поиском служб.";
    public string CompactStatus => _snapshot.Stage switch
    {
        AuditStage.Preparing => "Поиск устройств и подготовка целей…",
        AuditStage.Scanning or AuditStage.Detecting => $"Проверка портов и служб: {_snapshot.Progress.Checked:N0}/{_snapshot.Progress.Total:N0} · подтверждено: {_snapshot.Progress.Identified}",
        AuditStage.FindingSites => $"Поиск сайтов и страниц · {_allRows.Sum(r => r.HttpSites.Sum(s => s.Pages.Count))} страниц",
        AuditStage.Completed when !_snapshot.TargetServicesOnly => $"Аудит завершён. Открыто портов: {_snapshot.Progress.Open} · определено служб: {_snapshot.Progress.Identified}",
        AuditStage.Completed => MatchedEndpointCount == 0 ? "Поиск завершён. Подходящие службы не найдены." :
            $"Поиск завершён. Подтверждено целевых служб: {MatchedEndpointCount} · узлов: {MatchedHostCount}",
        AuditStage.Cancelled => "Поиск остановлен. Частичные результаты сохранены.",
        AuditStage.NetworkChanged => "Сеть изменилась. Поиск остановлен.",
        AuditStage.Failed => "Поиск завершился с ошибкой. Сохранены доступные результаты.",
        _ => StatusText
    };
    public int DeviceCount => Session.Current.Network is { } network && Devices.SelectedNetwork?.HasSameContext(network) == true ? Devices.KnownCount : 0;
    public IReadOnlyList<string> Profiles { get; } = ["Быстрый", "Стандартный (1–1024 + основные)", "Полный (1–65535)", "Пользовательский"];
    public IReadOnlyList<string> ServiceFilters { get; } = ["Все службы", "HTTP", "HTTPS", "SSH", "FTP", "RDP", "SMB", "SMTP", "TLS", "Unknown"];
    public ObservableCollection<AuditRow> Rows { get; } = [];
    public ObservableCollection<TargetHostSummary> Hosts { get; } = [];
    public IReadOnlyList<AuditTarget> FullScanTargets { get; private set; } = [];
    public IReadOnlyList<string> DisplayModes { get; } = ["Все результаты", "Только SMB / FTP / Web"];
    public bool IsTargetOnly => SelectedDisplayModeIndex == 1;
    public bool IsPreparingDiscovery => IsAuditing && _snapshot.Stage == AuditStage.Preparing && Devices.IsBusy;
    public bool IsResultsEmpty => Rows.Count == 0;
    public int MatchedHostCount => _snapshot.Hosts.Count(h => h.HasMatch);
    public int MatchedEndpointCount => _snapshot.Hosts.Sum(h => h.EndpointCount);
    public string CheckedPortsText => _snapshot.AuditId == Guid.Empty ? "Порты ещё не проверялись." :
        $"{(_snapshot.TargetServicesOnly || _snapshot.Profile == PortProfile.Targeted ? "Целевой поиск" : "Обычный аудит")}. TCP-порты текущего запуска: {PortScanProfiles.Describe(_snapshot.CheckedPorts)}. Набор каждого IP показан в разделе «По узлам».";
    public string ScopeNote => _snapshot.ScopeNote;
    public string TargetStatusText
    {
        get
        {
            if (_snapshot.AuditId == Guid.Empty) return "Проверка целевых служб ещё не выполнена.";
            var pending = _snapshot.Hosts.Count(h => h.State == TargetHostState.Pending);
            var scanning = _snapshot.Hosts.Count(h => h.State == TargetHostState.Scanning);
            var partial = _snapshot.Hosts.Count(h => h.IsPartial);
            var counts = $"Подходящих узлов: {MatchedHostCount}; подтверждённых целевых служб: {MatchedEndpointCount}.";
            if (_snapshot.IsRunning) return $"{counts} Проверено узлов: {_snapshot.Progress.HostsCompleted}/{_snapshot.Progress.HostsTotal}. Ожидают: {pending}; проверяются: {scanning}.";
            if (_snapshot.Stage is AuditStage.Cancelled or AuditStage.Failed or AuditStage.NetworkChanged || partial > 0)
                return $"{counts} Проверка неполная. Найденные совпадения сохранены; непроверенные и неответившие узлы не считаются узлами без служб.";
            return MatchedHostCount > 0 ? counts : "Не найдено подтверждённых SMB/FTP/HTTP/HTTPS-служб среди проверенных портов.";
        }
    }
    public string EmptyResultsText => !HasAudit ? "Здесь появятся найденные службы и сайты." : IsTargetOnly ? MatchedHostCount > 0
        ? "Нет целевых служб, соответствующих дополнительным фильтрам." : TargetStatusText
        : _snapshot.AuditId == Guid.Empty ? "Аудит ещё не выполнялся." : _snapshot.IsRunning
            ? "Проверка продолжается; результатов для отображения пока нет." : "Нет результатов для выбранных фильтров.";
    public bool CanConfigure => !IsAuditing && !IsBusy && !Devices.IsBusy && !Devices.IsMonitoring;
    public bool HasError => ErrorMessage.Length > 0;
    public bool HasFilterError => FilterError.Length > 0;
    public bool IsCustomProfile => SelectedProfileIndex == 3;
    public bool IsFullProfile => SelectedProfileIndex == 2;
    public string SelectionDetails => SelectedRow?.Details ?? "Выберите строку, чтобы увидеть ответ протокола и сведения об определении службы.";
    public IReadOnlyList<HttpSiteResult> SelectedSites => SelectedRow?.HttpSites ?? [];
    public bool HasSites => SelectedSites.Count > 0;
    public IReadOnlyList<HttpPage> SelectedPages => SelectedSite?.Pages ?? [];
    public string SiteDetails => SelectedSite?.Details ?? "Выберите HTTP-результат службы.";
    public string WebProgressText => $"HTTP-результатов: {_allRows.Sum(r => r.HttpSites.Count)} · Проверяются: {_allRows.Sum(r => r.HttpSites.Count(s => s.State == HttpSiteState.Checking))} · HTML-страниц: {_allRows.Sum(r => r.HttpSites.Sum(s => s.Pages.Count))}";
    public string ResultCount => $"Показано: {Rows.Count} из {_allRows.Count}";
    [ObservableProperty, NotifyCanExecuteChangedFor(nameof(RefreshDevicesCommand), nameof(DisconnectCommand), nameof(StartAuditCommand), nameof(FindTargetServersCommand), nameof(FindAllSitesOnDeviceCommand)), NotifyPropertyChangedFor(nameof(CanConfigure))]
    private bool _isBusy;
    [ObservableProperty, NotifyCanExecuteChangedFor(nameof(RefreshDevicesCommand), nameof(StartAuditCommand), nameof(FindTargetServersCommand), nameof(StopAuditCommand), nameof(FindAllSitesOnDeviceCommand)), NotifyPropertyChangedFor(nameof(CanConfigure))]
    private bool _isAuditing;
    [ObservableProperty, NotifyPropertyChangedFor(nameof(HasError))] private string _errorMessage = string.Empty;
    [ObservableProperty] private string _statusText = "Аудит ещё не запускался.";
    [ObservableProperty] private string _progressText = string.Empty;
    [ObservableProperty] private bool _isAdvancedExpanded;
    [ObservableProperty] private bool _isDetailsExpanded;
    [ObservableProperty] private double _progressPercent;
    [ObservableProperty, NotifyPropertyChangedFor(nameof(IsCustomProfile), nameof(IsFullProfile))] private int _selectedProfileIndex;
    [ObservableProperty, NotifyPropertyChangedFor(nameof(IsTargetOnly))] private int _selectedDisplayModeIndex = 1;
    [ObservableProperty] private string _additionalTargetPorts = string.Empty;
    [ObservableProperty] private string _customPorts = "22,80,443,8000-8010";
    [ObservableProperty, NotifyCanExecuteChangedFor(nameof(FindAllSitesOnDeviceCommand))] private bool _includeLocal = true;
    [ObservableProperty, NotifyCanExecuteChangedFor(nameof(FindAllSitesOnDeviceCommand))] private AuditTarget? _selectedFullScanTarget;
    [ObservableProperty] private int _concurrency = 64;
    [ObservableProperty] private int _connectTimeoutMs = 650;
    [ObservableProperty] private string _searchText = string.Empty;
    [ObservableProperty] private string _portFilter = string.Empty;
    [ObservableProperty, NotifyPropertyChangedFor(nameof(HasFilterError))] private string _filterError = string.Empty;
    [ObservableProperty] private int _selectedServiceIndex;
    [ObservableProperty, NotifyPropertyChangedFor(nameof(SelectionDetails))] private AuditRow? _selectedRow;
    [ObservableProperty, NotifyPropertyChangedFor(nameof(SelectedPages), nameof(SiteDetails)), NotifyCanExecuteChangedFor(nameof(OpenSiteCommand))]
    private HttpSiteResult? _selectedSite;
    partial void OnSelectedRowChanged(AuditRow? value)
    {
        if (value is null) IsDetailsExpanded = false;
        if (value is not null && _detailEndpoint != (value.Address, value.Port)) IsDetailsExpanded = true;
        _detailEndpoint = value is null ? null : (value.Address, value.Port);
        if (value is not null) SelectedFullScanTarget = FullScanTargets.FirstOrDefault(t => t.Address.Equals(value.Target.Address));
        var origin = SelectedSite?.Origin;
        SelectedSite = value?.HttpSites.FirstOrDefault(s => s.Origin == origin) ?? value?.HttpSites.FirstOrDefault();
        OnPropertyChanged(nameof(SelectedSites)); OnPropertyChanged(nameof(HasSites));
    }
    private bool CanOpenSite() => SelectedSite is { HttpConfirmed: true } site && Uri.TryCreate(site.Url, UriKind.Absolute, out var uri) && uri.Scheme == "http" && uri.UserInfo.Length == 0;
    private (string Address, int Port)? _detailEndpoint;
    [RelayCommand(CanExecute = nameof(CanOpenSite))]
    private void OpenSite()
    {
        if (!CanOpenSite() || SelectedSite is null) return;
        try { Process.Start(new ProcessStartInfo(SelectedSite.Url) { UseShellExecute = true }); }
        catch (Exception ex) when (ex is System.ComponentModel.Win32Exception or InvalidOperationException)
        { ErrorMessage = "Не удалось открыть системный браузер. Адрес: " + SelectedSite.Url; }
    }
    partial void OnSelectedDisplayModeIndexChanged(int value) => FilterRows();
    partial void OnSearchTextChanged(string value) => FilterRows();
    partial void OnPortFilterChanged(string value) => FilterRows();
    partial void OnSelectedServiceIndexChanged(int value) => FilterRows();
    private bool CanRefreshDevices() => !_disposed && Session.IsReady && !IsBusy && !IsAuditing && !Devices.IsBusy && !Devices.IsMonitoring;
    private bool CanDisconnect() => !_disposed && Session.CanDisconnectWifi && !Session.IsConnecting && !IsBusy;
    private bool CanStartAudit() => !_disposed && _audit is not null && !_audit.Current.IsRunning && Session.IsReady && !IsBusy && !IsAuditing && !Devices.IsBusy && !Devices.IsMonitoring;
    private bool CanPrimaryAction() => !_disposed && !IsBusy && (IsAuditing || !Session.IsReady && !Session.IsConnecting && !Session.IsObtainingAddress || CanStartAudit());
    [RelayCommand(CanExecute = nameof(CanPrimaryAction), AllowConcurrentExecutions = true)]
    private async Task PrimaryActionAsync()
    {
        if (IsAuditing) await StopAsync();
        else if (!Session.IsReady) NavigationRequested?.Invoke("Устройства");
        else await FindTargetServersAsync();
    }
    partial void OnIsBusyChanged(bool value) => NotifyWorkflow();
    partial void OnIsAuditingChanged(bool value) => NotifyWorkflow();
    private void NotifyWorkflow()
    {
        foreach (var property in new[] { nameof(HasAudit), nameof(PrimaryActionText), nameof(ReadinessText), nameof(CompactStatus), nameof(CanConfigure) }) OnPropertyChanged(property);
        PrimaryActionCommand.NotifyCanExecuteChanged();
    }
    private bool CanStopAudit() => IsAuditing;
    private bool CanFindAllSitesOnDevice() => CanStartAudit() && SelectedFullScanTarget is { } target &&
        (!target.IsLocal || IncludeLocal) && FullScanTargets.Any(t => t.Address.Equals(target.Address));
    [RelayCommand(CanExecute = nameof(CanRefreshDevices))]
    private async Task RefreshDevicesAsync()
    {
        if (!CanRefreshDevices() || Session.Current.Network is not { } network) return;
        IsBusy = true; ErrorMessage = string.Empty;
        try { Devices.UseSessionNetwork(network); if (Devices.ScanCommand.CanExecute(null)) await Devices.ScanCommand.ExecuteAsync(null); }
        finally { IsBusy = false; }
    }
    [RelayCommand(CanExecute = nameof(CanDisconnect))]
    private async Task DisconnectAsync()
    {
        if (!CanDisconnect()) return;
        IsBusy = true; ErrorMessage = string.Empty;
        try { ErrorMessage = (await _connections.DisconnectAsync()).FailureReason; }
        finally { IsBusy = false; }
    }
    [RelayCommand(CanExecute = nameof(CanStartAudit))]
    private async Task StartAuditAsync()
    {
        if (!CanStartAudit() || _audit is null) return;
        ErrorMessage = string.Empty;
        SelectedDisplayModeIndex = 0;
        try { await _audit.RunAsync(new((PortProfile)SelectedProfileIndex, CustomPorts, IncludeLocal, Concurrency, ConnectTimeoutMs)); }
        catch (Exception ex) when (ex is ArgumentException or InvalidOperationException) { ErrorMessage = ex.Message; }
        catch (OperationCanceledException) { }
    }
    [RelayCommand(CanExecute = nameof(CanStartAudit))]
    private async Task FindTargetServersAsync()
    {
        if (!CanStartAudit() || _audit is null || Session.Current.Network is not { } network) return;
        ErrorMessage = string.Empty;
        SelectedDisplayModeIndex = 1;
        Devices.UseSessionNetwork(network);
        var profile = SelectedProfileIndex == 0 ? PortProfile.Targeted : (PortProfile)SelectedProfileIndex;
        try { await _audit.RunAsync(new(profile, profile == PortProfile.Custom ? CustomPorts : "", IncludeLocal, Concurrency, ConnectTimeoutMs)
            { TargetServicesOnly = true, AdditionalPorts = AdditionalTargetPorts }); }
        catch (Exception ex) when (ex is ArgumentException or InvalidOperationException) { ErrorMessage = ex.Message; }
        catch (OperationCanceledException) { }
    }
    [RelayCommand(CanExecute = nameof(CanFindAllSitesOnDevice))]
    private async Task FindAllSitesOnDeviceAsync()
    {
        if (!CanFindAllSitesOnDevice() || _audit is null || SelectedFullScanTarget is not { } target) return;
        ErrorMessage = string.Empty; SelectedDisplayModeIndex = 1;
        try { await _audit.RunAsync(new(PortProfile.Full, IncludeLocal: IncludeLocal, Concurrency: Concurrency, ConnectTimeoutMs: ConnectTimeoutMs)
            { TargetServicesOnly = true, TargetAddress = target.Address }); }
        catch (Exception ex) when (ex is ArgumentException or InvalidOperationException) { ErrorMessage = ex.Message; }
        catch (OperationCanceledException) { }
    }
    [RelayCommand(CanExecute = nameof(CanStopAudit))]
    private Task StopAuditAsync() => StopAsync();
    private void OnAuditUpdated(object? sender, AuditSnapshot snapshot)
    {
        if (Dispatcher.UIThread.CheckAccess()) { Apply(snapshot); return; }
        lock (_dispatchGate)
        {
            if (_pendingSnapshot is null || snapshot.Version > _pendingSnapshot.Version) _pendingSnapshot = snapshot;
            if (_updateQueued) return;
            _updateQueued = true;
        }
        Dispatcher.UIThread.Post(() =>
        {
            AuditSnapshot? latest;
            lock (_dispatchGate) { latest = _pendingSnapshot; _pendingSnapshot = null; _updateQueued = false; }
            if (latest is not null) Apply(latest);
        });
    }
    private void Apply(AuditSnapshot snapshot, bool force = false)
    {
        if (_disposed || !force && snapshot.Version <= _version) return;
        if (_audit is not null && snapshot.AuditId != _audit.Current.AuditId) return;
        _version = Math.Max(_version, snapshot.Version);
        IsAuditing = snapshot.IsRunning; StatusText = snapshot.Message;
        var p = snapshot.Progress;
        ProgressPercent = p.Total == 0 ? 0 : 100d * p.Checked / p.Total;
        ProgressText = $"Устройства: {p.HostsCompleted}/{p.HostsTotal} · TCP-порты: {p.Checked}/{p.Total} · Открыто: {p.Open} · Служб подтверждено: {p.Identified}\nЗакрыто: {p.Closed} · Таймаут: {p.TimedOut} · Недоступно: {p.Unavailable} · Ошибки: {p.Errors} · Время: {p.Elapsed:hh\\:mm\\:ss}";
        // A queued update from the previous session must not put old rows back into the UI.
        _snapshot = snapshot.SessionId == Session.Current.SessionId && Session.IsReady ? snapshot : AuditSnapshot.Empty;
        var selectedAddress = SelectedFullScanTarget?.Address;
        FullScanTargets = _snapshot.Hosts.Where(h => h.SessionId == _snapshot.SessionId && h.AuditId == _snapshot.AuditId).Select(h => h.Target).ToArray();
        SelectedFullScanTarget = FullScanTargets.FirstOrDefault(t => t.Address.Equals(selectedAddress));
        OnPropertyChanged(nameof(FullScanTargets)); FindAllSitesOnDeviceCommand.NotifyCanExecuteChanged();
        _allRows = _snapshot.Rows.Where(r => r.SessionId == _snapshot.SessionId && r.AuditId == _snapshot.AuditId).ToArray();
        OnPropertyChanged(nameof(WebProgressText));
        foreach (var property in new[] { nameof(MatchedHostCount), nameof(MatchedEndpointCount), nameof(TargetStatusText), nameof(CheckedPortsText), nameof(ScopeNote), nameof(IsPreparingDiscovery) }) OnPropertyChanged(property);
        FilterRows();
        NotifyWorkflow();
    }
    private void FilterRows()
    {
        var selected = SelectedRow;
        var portText = PortFilter.Trim(); int port = 0;
        var valid = portText.Length == 0 || int.TryParse(portText, NumberStyles.None, CultureInfo.InvariantCulture, out port) && port is >= 1 and <= 65535;
        FilterError = valid ? "" : "Фильтр порта: число от 1 до 65535.";
        var service = SelectedServiceIndex > 0 && SelectedServiceIndex < ServiceFilters.Count ? ServiceFilters[SelectedServiceIndex] : "";
        var search = SearchText.Trim();
        var rows = _allRows.Where(r => (!IsTargetOnly || TargetServiceMatcher.Matches(r, _snapshot.SessionId, _snapshot.AuditId)) && valid && (port == 0 || r.Port == port) &&
            (service.Length == 0 || (service == "SMB" ? r.Protocol.StartsWith("SMB", StringComparison.Ordinal) : r.Protocol == service)) &&
            (search.Length == 0 || $"{r.Address} {r.Name} {r.Protocol} {r.Product} {r.Version}".Contains(search, StringComparison.OrdinalIgnoreCase)))
            .OrderBy(r => Convert.ToHexString(r.Target.Address.GetAddressBytes()), StringComparer.Ordinal).ThenBy(r => r.Port).ToArray();
        SynchronizeRows(Rows, rows);
        var addresses = rows.Select(r => r.Target.Address).ToHashSet();
        var hasEndpointFilter = search.Length > 0 || portText.Length > 0 || service.Length > 0;
        SynchronizeRows(Hosts, _snapshot.Hosts.Where(h => h.SessionId == _snapshot.SessionId && h.AuditId == _snapshot.AuditId &&
            (!IsTargetOnly || h.HasMatch) && (!hasEndpointFilter || addresses.Contains(h.Target.Address))).ToArray());
        OnPropertyChanged(nameof(IsResultsEmpty)); OnPropertyChanged(nameof(EmptyResultsText));
        SelectedRow = selected is null ? null : rows.FirstOrDefault(r => r.Target.Address.Equals(selected.Target.Address) && r.Port == selected.Port);
        OnPropertyChanged(nameof(ResultCount));
    }
    private void OnStateChanged(object? sender, PropertyChangedEventArgs e)
    {
        OnPropertyChanged(nameof(DeviceCount));
        OnPropertyChanged(nameof(IsPreparingDiscovery));
        if (ReferenceEquals(sender, Session) && _audit is not null) Apply(_audit.Current, force: true);
        NotifyWorkflow();
        RefreshDevicesCommand.NotifyCanExecuteChanged(); DisconnectCommand.NotifyCanExecuteChanged(); StartAuditCommand.NotifyCanExecuteChanged(); FindTargetServersCommand.NotifyCanExecuteChanged(); FindAllSitesOnDeviceCommand.NotifyCanExecuteChanged();
    }
    public Task StopAsync() => _audit?.StopAsync() ?? Task.CompletedTask;
    public void Dispose()
    {
        if (_disposed) return; _disposed = true;
        Session.PropertyChanged -= OnStateChanged; Devices.PropertyChanged -= OnStateChanged;
        if (_audit is not null) { _audit.Updated -= OnAuditUpdated; _ = _audit.StopAsync(); }
    }
}
