using System.Collections.ObjectModel;
using System.ComponentModel;
using System.Globalization;
using System.Diagnostics;
using Avalonia.Threading;
using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;
using WirelessSecurityAnalyzer.Core.Interfaces;
using WirelessSecurityAnalyzer.Core.NetworkAudit;
using WirelessSecurityAnalyzer.App.Services;

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
    private bool _synchronizingRows;
    public NetworkAuditViewModel(NetworkSessionViewModel session, DevicesViewModel devices, IWifiConnectionService connections,
        INetworkAuditService? audit = null, LoggingSettingsService? preferences = null,
        IEnumerable<IResourceCatalogReader>? catalogReaders = null, ILocalNetworkService? networks = null)
    {
        Session = session; Devices = devices; _connections = connections; _audit = audit;
        Catalog = new(catalogReaders ?? [], networks);
        Catalog.SummaryChanged += FilterRows;
        _selectedProfileIndex = 0;
        _includeLocal = preferences?.UserPreferences.IncludeLocal ?? true;
        Session.PropertyChanged += OnStateChanged; Devices.PropertyChanged += OnStateChanged;
        if (_audit is not null) { _audit.Updated += OnAuditUpdated; Apply(_audit.Current); }
    }
    public NetworkSessionViewModel Session { get; }
    public DevicesViewModel Devices { get; }
    public ResourceCatalogViewModel Catalog { get; }
    public bool HasFileService => SelectedRow?.HasFileService == true;
    public string FileServiceEvidence => HasFileService ? SelectedRow!.Service.Evidence : "";
    public bool HasAudit => _snapshot.AuditId != Guid.Empty;
    public string PrimaryActionText => IsAuditing ? "Остановить" : Session.IsObtainingAddress ? "Получение IPv4…" : "Найти серверы";
    public string ReadinessText => IsAuditing ? "" : Session.IsObtainingAddress ? "Wi-Fi подключён. Дождитесь получения IPv4; при необходимости отмените подключение." :
        Session.IsConnecting ? "Дождитесь завершения подключения к Wi-Fi." : !Session.IsReady ? "Выберите активный IPv4-интерфейс во вкладке «Устройства»." :
        Devices.IsMonitoring ? "Сначала остановите мониторинг в разделе «Устройства»." :
        Devices.IsBusy ? "Выполняется поиск устройств. Дождитесь завершения или остановите его в разделе «Устройства»." :
        !Devices.CanOpenAudit ? "Сначала завершите поиск устройств для выбранного интерфейса." : "";
    public bool HasReadinessMessage => ReadinessText.Length > 0;
    public string ContextSummary => Session.IsReady ? $"{Session.InterfaceName} · {Session.Ipv4}/{Session.Current.PrefixLength}" : "Сеть не выбрана";
    public bool ShowAuditStatus => Session.IsReady || HasAudit || StatusText != "Аудит ещё не запускался.";
    public string AuditNotice
    {
        get
        {
            if (_snapshot.Stage != AuditStage.Completed) return "";
            var progress = _snapshot.Progress;
            var reasons = new List<string>();
            if (progress.TimedOut > 0) reasons.Add($"без ответа ({progress.TimedOut})");
            if (progress.Unavailable > 0) reasons.Add($"недоступно ({progress.Unavailable})");
            if (progress.Errors > 0) reasons.Add($"ошибки ({progress.Errors})");
            var unconfirmed = _allRows.Count(r => r.Service.Confidence != ServiceConfidence.High);
            if (unconfirmed > 0) reasons.Add($"протокол не подтверждён ({unconfirmed})");

            var tcpNotice = reasons.Count > 0 ? $"Неполные сетевые проверки: {string.Join(", ", reasons)}." :
                _snapshot.Hosts.Any(h => h.IsPartial) ? "Часть сетевых проверок не завершена." : "";
            if (!_allRows.Any(r => r.HttpSites.Any(s => s.IsPartial || s.State is HttpSiteState.AccessRestricted or HttpSiteState.ConnectionError)))
                return tcpNotice;

            const string httpNotice = "Есть ограничения при проверке HTTP-страниц. Выберите службу для подробностей.";
            return tcpNotice.Length == 0 ? httpNotice : tcpNotice + " " + httpNotice;
        }
    }
    public bool HasAuditNotice => AuditNotice.Length > 0;
    public string CompactStatus => _snapshot.Stage switch
    {
        AuditStage.Preparing => "Поиск устройств и подготовка целей…",
        AuditStage.Scanning or AuditStage.Detecting => $"Проверено устройств: {_snapshot.Progress.HostsCompleted}/{_snapshot.Progress.HostsTotal} · TCP: {_snapshot.Progress.Checked:N0}/{_snapshot.Progress.Total:N0} · служб: {_snapshot.Progress.Identified}",
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
    public static IReadOnlyList<string> PortProfiles { get; } = ["Быстрый", "Стандартный", "Полный", "Пользовательский"];
    public IReadOnlyList<string> Profiles => PortProfiles;
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
    public bool CanEditParameters => IsCustomProfile && CanConfigure;
    public bool EffectiveIncludeLocal => SelectedProfileIndex is 0 or 1 || IncludeLocal;
    public string CustomPortsError
    {
        get
        {
            if (!IsCustomProfile) return "";
            try { PortScanProfiles.Parse(CustomPorts); return ""; }
            catch (ArgumentException ex) { return ex.Message; }
        }
    }
    public bool HasCustomPortsError => CustomPortsError.Length > 0;
    public bool IsFullProfile => SelectedProfileIndex == 2;
    public string SelectionDetails => SelectedRow?.Details ?? "Выберите строку, чтобы увидеть ответ протокола и сведения об определении службы.";
    public bool HasSelection => SelectedRow is not null;
    public string SelectionHeading => SelectedRow is { } row ? $"{row.Address}:{row.Port} · {row.Protocol}" : "Сведения о службе";
    public string SelectionProduct => SelectedSite is { Server.Length: > 0 } site ? site.Server : SelectedRow is { } row
        ? row.Product + (!string.IsNullOrWhiteSpace(row.Service.Version) && row.Service.Version != "-" &&
            !row.Product.Contains(row.Service.Version, StringComparison.OrdinalIgnoreCase) ? " · " + row.Service.Version : "") : "";
    public string SelectionStatus => SelectedSite is not null ? SiteStatus : SelectedRow is { } row ?
        row.Service.Confidence == ServiceConfidence.Unknown ? "Протокол не подтверждён." : "Определение службы: " + row.Confidence : "Выберите строку службы.";
    public bool HasHttpExchange => SelectedSite?.Exchange is not null;
    public string HttpRequestText => SelectedSite?.Exchange?.Request ?? "";
    public string HttpResponseText => SelectedSite?.Exchange is { Response.Length: > 0 } exchange ? exchange.Response : "Ответ не получен.";
    public string SiteAddress => SelectedSite?.DisplayUrl ?? "";
    public bool HasMultipleSites => SelectedSites.Count > 1;
    public string SitePosition => $"Сайт {SelectedSites.ToList().IndexOf(SelectedSite!)+1} из {SelectedSites.Count}";
    [RelayCommand(CanExecute = nameof(HasMultipleSites))]
    private void PreviousSite() => SelectRelativeSite(-1);
    [RelayCommand(CanExecute = nameof(HasMultipleSites))]
    private void NextSite() => SelectRelativeSite(1);
    private void SelectRelativeSite(int offset)
    {
        if (!HasMultipleSites) return;
        var index = SelectedSites.ToList().IndexOf(SelectedSite!);
        SelectedSite = SelectedSites[(index + offset + SelectedSites.Count) % SelectedSites.Count];
    }
    public string HttpAvailabilityText => HasSites ? "" : SelectedRow?.Protocol switch
    {
        "HTTP" => "Результаты проверки HTTP-страниц пока не получены.",
        "HTTPS" => "Служба HTTPS распознана. Обход HTTPS-страниц не поддерживается.",
        null => "",
        _ => "Поиск HTTP-страниц для этой службы не выполнялся."
    };
    public IReadOnlyList<HttpSiteResult> SelectedSites => SelectedRow?.HttpSites ?? [];
    public bool HasSites => SelectedSites.Count > 0;
    public IReadOnlyList<HttpPage> SelectedPages => SelectedSite?.Pages ?? [];
    public string SiteDetails => SelectedSite?.Details ?? "Выберите HTTP-результат службы.";
    public string SiteStatus => SelectedSite is { } site ? $"{site.StateText}{(site.IsPartial ? " · неполный результат" : "")}\n{site.Message}".Trim() : "";
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
    partial void OnIsAdvancedExpandedChanged(bool value)
    { if (value && !CanEditParameters) IsAdvancedExpanded = false; }
    partial void OnSelectedProfileIndexChanged(int value)
    {
        if (!IsCustomProfile) IsAdvancedExpanded = false;
        NotifyPortConfiguration();
    }
    partial void OnCustomPortsChanged(string value) => NotifyPortConfiguration();
    partial void OnIncludeLocalChanged(bool value) => OnPropertyChanged(nameof(EffectiveIncludeLocal));
    private void NotifyPortConfiguration()
    {
        foreach (var name in new[] { nameof(CustomPortsError), nameof(HasCustomPortsError), nameof(CanEditParameters), nameof(EffectiveIncludeLocal) }) OnPropertyChanged(name);
        StartAuditCommand.NotifyCanExecuteChanged(); FindTargetServersCommand.NotifyCanExecuteChanged();
        PrimaryActionCommand.NotifyCanExecuteChanged(); FindAllSitesOnDeviceCommand.NotifyCanExecuteChanged();
    }
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
    [ObservableProperty, NotifyPropertyChangedFor(nameof(SelectedPages), nameof(SiteDetails), nameof(SiteStatus), nameof(SelectionProduct), nameof(SelectionStatus), nameof(HasHttpExchange), nameof(HttpRequestText), nameof(HttpResponseText), nameof(SiteAddress), nameof(SitePosition)), NotifyCanExecuteChangedFor(nameof(OpenSiteCommand))]
    private HttpSiteResult? _selectedSite;
    partial void OnSelectedRowChanged(AuditRow? value)
    {
        if (_synchronizingRows) return;
        Catalog.Select(value, Session.Current.Network);
        if (value is null) IsDetailsExpanded = false;
        if (value is not null && _detailEndpoint != (value.Address, value.Port)) IsDetailsExpanded = true;
        _detailEndpoint = value is null ? null : (value.Address, value.Port);
        if (value is not null) SelectedFullScanTarget = FullScanTargets.FirstOrDefault(t => t.Address.Equals(value.Target.Address));
        var origin = SelectedSite?.Origin;
        // Publish the new list before selection: Avalonia cannot select an item in the previous list.
        OnPropertyChanged(nameof(SelectedSites)); OnPropertyChanged(nameof(HasSites)); OnPropertyChanged(nameof(HasMultipleSites));
        PreviousSiteCommand.NotifyCanExecuteChanged(); NextSiteCommand.NotifyCanExecuteChanged();
        SelectedSite = value?.HttpSites.FirstOrDefault(s => s.Origin == origin) ?? value?.HttpSites.FirstOrDefault();
        foreach (var name in new[] { nameof(HasSelection), nameof(SelectionHeading), nameof(SelectionProduct), nameof(HttpAvailabilityText), nameof(SelectionStatus), nameof(SitePosition), nameof(HasFileService), nameof(FileServiceEvidence) }) OnPropertyChanged(name);
        ToggleDetailsCommand.NotifyCanExecuteChanged();
    }
    private bool CanToggleDetails() => HasSelection;
    [RelayCommand(CanExecute = nameof(CanToggleDetails))]
    private void ToggleDetails()
    {
        if (HasFileService) Catalog.IsExpanded = !Catalog.IsExpanded;
        else if (HasSelection) IsDetailsExpanded = !IsDetailsExpanded;
    }
    private bool CanOpenSite() => SelectedSite is { HttpConfirmed: true } site && Uri.TryCreate(site.Url, UriKind.Absolute, out var uri) && uri.Scheme == "http" && uri.UserInfo.Length == 0;
    private (string Address, int Port)? _detailEndpoint;
    [RelayCommand(CanExecute = nameof(CanOpenSite))]
    private void OpenSite()
    {
        if (!CanOpenSite() || SelectedSite is null) return;
        try { Process.Start(new ProcessStartInfo(SelectedSite.Url) { UseShellExecute = true }); }
        catch (Exception ex) when (ex is System.ComponentModel.Win32Exception or InvalidOperationException)
        { ErrorMessage = "Не удалось открыть системный браузер. Адрес: " + SiteAddress; }
    }
    partial void OnSelectedDisplayModeIndexChanged(int value) => FilterRows();
    partial void OnSearchTextChanged(string value) => FilterRows();
    partial void OnPortFilterChanged(string value) => FilterRows();
    partial void OnSelectedServiceIndexChanged(int value) => FilterRows();
    private bool CanRefreshDevices() => !_disposed && Session.IsReady && !IsBusy && !IsAuditing && !Devices.IsBusy && !Devices.IsMonitoring;
    private bool CanDisconnect() => !_disposed && Session.CanDisconnectWifi && !Session.IsConnecting && !IsBusy;
    private bool CanStartAudit() => !_disposed && _audit is not null && !_audit.Current.IsRunning && Session.IsReady && Devices.CanOpenAudit && !HasCustomPortsError && !IsBusy && !IsAuditing && !Devices.IsBusy && !Devices.IsMonitoring;
    private bool CanPrimaryAction() => !_disposed && !IsBusy && (IsAuditing || CanStartAudit());
    [RelayCommand(CanExecute = nameof(CanPrimaryAction), AllowConcurrentExecutions = true)]
    private async Task PrimaryActionAsync()
    {
        if (IsAuditing) await StopAsync();
        else await FindTargetServersAsync();
    }
    partial void OnIsBusyChanged(bool value) => NotifyWorkflow();
    partial void OnIsAuditingChanged(bool value) => NotifyWorkflow();
    private void NotifyWorkflow()
    {
        foreach (var property in new[] { nameof(HasAudit), nameof(PrimaryActionText), nameof(ReadinessText), nameof(HasReadinessMessage), nameof(ContextSummary), nameof(ShowAuditStatus), nameof(AuditNotice), nameof(HasAuditNotice), nameof(CompactStatus), nameof(CanConfigure), nameof(CanEditParameters) }) OnPropertyChanged(property);
        PrimaryActionCommand.NotifyCanExecuteChanged();
        ToggleDetailsCommand.NotifyCanExecuteChanged();
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
        try { await _audit.RunAsync(new((PortProfile)SelectedProfileIndex, CustomPorts, EffectiveIncludeLocal, Concurrency, ConnectTimeoutMs)); }
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
        try { await _audit.RunAsync(new(profile, profile == PortProfile.Custom ? CustomPorts : "", EffectiveIncludeLocal, Concurrency, ConnectTimeoutMs)
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
        Catalog.SetScope(_snapshot.AuditId);
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
        var selectedOrigin = SelectedSite?.Origin; var detailsExpanded = IsDetailsExpanded;
        var portText = PortFilter.Trim(); int port = 0;
        var valid = portText.Length == 0 || int.TryParse(portText, NumberStyles.None, CultureInfo.InvariantCulture, out port) && port is >= 1 and <= 65535;
        FilterError = valid ? "" : "Фильтр порта: число от 1 до 65535.";
        var service = SelectedServiceIndex > 0 && SelectedServiceIndex < ServiceFilters.Count ? ServiceFilters[SelectedServiceIndex] : "";
        var search = SearchText.Trim();
        var rows = _allRows.Where(r => (!IsTargetOnly || TargetServiceMatcher.Matches(r, _snapshot.SessionId, _snapshot.AuditId)) && valid && (port == 0 || r.Port == port) &&
            (service.Length == 0 || (service == "SMB" ? r.Protocol.StartsWith("SMB", StringComparison.Ordinal) : r.Protocol == service)) &&
            (search.Length == 0 || $"{r.Address} {r.Name} {r.Protocol} {r.Product} {r.Version}".Contains(search, StringComparison.OrdinalIgnoreCase)))
            .OrderByDescending(r => r.HighlightResult).ThenByDescending(r => r.HasFoundSite)
            .ThenBy(r => Convert.ToHexString(r.Target.Address.GetAddressBytes()), StringComparer.Ordinal).ThenBy(r => r.Port)
            .Select(r => r.HasFileService && Catalog.Summary(r) != r.CatalogSummary
                ? r with { CatalogSummary = Catalog.Summary(r) } : r).ToArray();
        var selectedResult = selected is null ? null : rows.FirstOrDefault(r => r.AuditId == selected.AuditId &&
            r.Target.Address.Equals(selected.Target.Address) && r.Port == selected.Port);
        _synchronizingRows = true;
        try { SynchronizeRows(Rows, rows); }
        finally { _synchronizingRows = false; }
        var addresses = rows.Select(r => r.Target.Address).ToHashSet();
        var hasEndpointFilter = search.Length > 0 || portText.Length > 0 || service.Length > 0;
        SynchronizeRows(Hosts, _snapshot.Hosts.Where(h => h.SessionId == _snapshot.SessionId && h.AuditId == _snapshot.AuditId &&
            (!IsTargetOnly || h.HasMatch) && (!hasEndpointFilter || addresses.Contains(h.Target.Address))).ToArray());
        OnPropertyChanged(nameof(IsResultsEmpty)); OnPropertyChanged(nameof(EmptyResultsText));
        SelectedRow = selectedResult is null ? null : Rows.FirstOrDefault(r => r.Equals(selectedResult));
        if (SelectedRow is not null && selected is not null)
        {
            IsDetailsExpanded = detailsExpanded;
            SelectedSite = SelectedSites.FirstOrDefault(site => site.Origin == selectedOrigin) ?? SelectedSites.FirstOrDefault();
        }
        else if (SelectedRow is null) { Catalog.Select(null, null); IsDetailsExpanded = false; }
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
        Catalog.Stop();
        Catalog.SummaryChanged -= FilterRows;
        Session.PropertyChanged -= OnStateChanged; Devices.PropertyChanged -= OnStateChanged;
        if (_audit is not null) { _audit.Updated -= OnAuditUpdated; _ = _audit.StopAsync(); }
    }
}
