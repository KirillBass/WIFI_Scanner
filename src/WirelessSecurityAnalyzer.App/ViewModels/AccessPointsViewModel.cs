using System.Collections.ObjectModel;
using System.ComponentModel;
using Avalonia.Threading;
using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;
using Serilog;
using WirelessSecurityAnalyzer.Core.Common;
using WirelessSecurityAnalyzer.Core.Interfaces;
using WirelessSecurityAnalyzer.Core.Models;
using WirelessSecurityAnalyzer.Core.Network;

namespace WirelessSecurityAnalyzer.App.ViewModels;

public sealed partial class AccessPointsViewModel : WifiViewModelBase
{
    private readonly IWifiScanner _scanner;
    private readonly IWifiAdapterService _adapterService;
    private readonly IWifiScanState _scanState;
    private readonly Dictionary<string, AccessPointRowViewModel> _rows = new(StringComparer.OrdinalIgnoreCase);
    private readonly CancellationTokenSource _lifetime = new();
    private long _snapshotVersion;
    private bool _stopped;
    private bool _lastAttemptFailed;
    private readonly IWifiConnectionService? _connections;
    public NetworkSessionViewModel? Session { get; }
    public event Action<WifiConnectionDialogViewModel>? ConnectionRequested;

    public AccessPointsViewModel(IWifiScanner scanner, IWifiAdapterService adapterService,
        ISystemSettingsService settings, ILogger logger, IWifiScanState scanState,
        IWifiConnectionService? connections = null, NetworkSessionViewModel? session = null) : base(settings, logger)
    {
        _scanner = scanner;
        _adapterService = adapterService;
        StatusText = "Нажмите «Сканировать», чтобы получить реальные данные Wi-Fi.";
        _scanState = scanState;
        _connections = connections;
        Session = session;
        if (Session is not null) Session.PropertyChanged += OnSessionChanged;
        _scanState.Updated += OnScanUpdated;
        if (_scanState.Current is { } snapshot) ApplySnapshot(snapshot);
    }

    public ObservableCollection<AccessPointRowViewModel> AccessPoints { get; } = [];
    public IReadOnlyList<string> BandFilters { get; } = ["Все диапазоны", "2,4 ГГц", "5 ГГц", "6 ГГц"];
    public int TotalCount => _rows.Count;
    public int Ghz24Count => _rows.Values.Count(r => r.AccessPoint.Band == WifiBand.Ghz2_4);
    public int Ghz5Count => _rows.Values.Count(r => r.AccessPoint.Band == WifiBand.Ghz5);
    public int Ghz6Count => _rows.Values.Count(r => r.AccessPoint.Band == WifiBand.Ghz6);
    public bool IsEmpty => AccessPoints.Count == 0;
    public bool HasSelectedAccessPoint => SelectedAccessPoint is not null;
    public bool HasSnapshot => _snapshotVersion > 0;
    public bool ShowScanStatus => HasScanAttempt || HasSnapshot;
    [ObservableProperty, NotifyPropertyChangedFor(nameof(ShowScanStatus))] private bool _hasScanAttempt;
    public bool AreResultsPrevious => HasSnapshot && (IsBusy || _lastAttemptFailed);
    public string ResultCaption => !HasSnapshot ? "Сканирование ещё не выполнялось" :
        $"{(AreResultsPrevious ? "Предыдущий снимок" : "Последний снимок")}: {TotalCount} точек доступа (BSS)";
    public string EmptyText => IsBusy ? "Сканирование эфира…" : !HasSnapshot ? "Нажмите «Сканировать», чтобы найти сети Wi-Fi." :
        SearchText.Length > 0 || SelectedBandIndex != 0 ? "Нет сетей, соответствующих фильтрам." : "Сканирование завершено. Точки доступа не найдены.";
    [ObservableProperty] private bool _hasAdapter;
    [ObservableProperty] private bool _isInitialized;

    [ObservableProperty] private string _searchText = string.Empty;
    [ObservableProperty] private AccessPointRowViewModel? _selectedAccessPoint;
    [ObservableProperty] private int _selectedBandIndex;
    [ObservableProperty] private bool _strongestFirst = true;
    [ObservableProperty, NotifyCanExecuteChangedFor(nameof(ConnectCommand))] private bool _isBusy;
    [ObservableProperty] private string _adapterText = "Проверка Wi-Fi адаптеров…";
    [ObservableProperty] private string _lastScanText = "Сканирование ещё не выполнялось";

    protected override string UnexpectedErrorMessage => "Не удалось выполнить операцию. Подробности сохранены в локальном журнале.";
    protected override string FailureStatus => "Не удалось просканировать эфир.";
    partial void OnIsBusyChanged(bool value) => NotifyScanPresentation();

    partial void OnSearchTextChanged(string value) => ApplyFilter();
    partial void OnSelectedAccessPointChanged(AccessPointRowViewModel? value)
    {
        OnPropertyChanged(nameof(HasSelectedAccessPoint));
        OnPropertyChanged(nameof(ConnectionHint));
        ConnectCommand.NotifyCanExecuteChanged();
    }
    partial void OnSelectedBandIndexChanged(int value) => ApplyFilter();
    partial void OnStrongestFirstChanged(bool value) => ApplyFilter();

    public string ConnectionHint => SelectedAccessPoint is not { } row ? "Выберите сеть для подключения." :
        row.AccessPoint.IsHidden || string.IsNullOrEmpty(row.AccessPoint.Ssid) ? "Подключение к скрытой сети без известного SSID не поддерживается." :
        !WifiConnectionPolicy.IsSupported(row.AccessPoint.Security) ? WifiConnectionPolicy.UnsupportedMessage(row.AccessPoint.Security) :
        row.AccessPoint.Security.GroupCipher == WifiCipherType.Tkip
            ? "Для подключения будет запрошен AES/CCMP; групповой шифр сети - TKIP. Windows выбирает точку данного SSID."
            : "Подключение выполняется к SSID; Windows выбирает подходящую точку доступа.";
    private bool CanConnect() => !_stopped && !IsBusy && _connections is not null && Session is { IsConnecting: false } &&
        SelectedAccessPoint is { AccessPoint.IsHidden: false } row && row.AccessPoint.Ssid.Length > 0 && WifiConnectionPolicy.IsSupported(row.AccessPoint.Security);
    [RelayCommand(CanExecute = nameof(CanConnect))]
    private void Connect()
    {
        if (SelectedAccessPoint is { } row && _connections is not null && Session is not null)
            ConnectionRequested?.Invoke(new(row.AccessPoint, _adapterService, _connections, Session));
    }
    private void OnSessionChanged(object? sender, PropertyChangedEventArgs e)
    { if (e.PropertyName == nameof(NetworkSessionViewModel.Current)) ConnectCommand.NotifyCanExecuteChanged(); }

    public async Task InitializeAsync()
    {
        try
        {
            var adapters = await _adapterService.GetAdaptersAsync(_lifetime.Token).ConfigureAwait(false);
            await Dispatcher.UIThread.InvokeAsync(() =>
            {
                AdapterText = adapters.Count == 0 ? "Wi-Fi адаптер не обнаружен" :
                    string.Join(" • ", adapters.Select(a => $"{a.Description} ({FormatAdapterState(a.State)})"));
                HasAdapter = adapters.Count > 0;
                SetError(adapters.Count == 0 ? new WifiException(WifiErrorKind.NoAdapter, "No adapter.") : null);
            });
        }
        catch (OperationCanceledException) when (_lifetime.IsCancellationRequested) { }
        catch (Exception exception)
        {
            Logger.Error(exception, "Adapter detection failed");
            await Dispatcher.UIThread.InvokeAsync(() => { AdapterText = "Адаптер недоступен"; HasAdapter = false; SetError(exception); });
        }
        finally { await Dispatcher.UIThread.InvokeAsync(() => IsInitialized = true); }
    }

    [RelayCommand]
    private Task RefreshAdaptersAsync() => InitializeAsync();

    [RelayCommand(IncludeCancelCommand = true)]
    private async Task ScanAsync(CancellationToken cancellationToken)
    {
        using var linked = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken, _lifetime.Token);
        IsBusy = true;
        HasScanAttempt = true;
        _lastAttemptFailed = true;
        NotifyScanPresentation();
        SetError(null);
        StatusText = "Сканирование эфира…";
        try
        {
            await _scanner.ScanAsync(linked.Token).ConfigureAwait(false);
            await Dispatcher.UIThread.InvokeAsync(() =>
            {
                if (_scanState.Current is { } snapshot) ApplySnapshot(snapshot);
            });
        }
        catch (OperationCanceledException) when (linked.IsCancellationRequested)
        {
            await Dispatcher.UIThread.InvokeAsync(() => StatusText = HasSnapshot ? "Сканирование отменено. Показан предыдущий снимок." : "Сканирование отменено.");
        }
        catch (Exception exception)
        {
            Logger.Error(exception, "Wi-Fi scan failed");
            await Dispatcher.UIThread.InvokeAsync(() => ShowError(exception));
        }
        finally { await Dispatcher.UIThread.InvokeAsync(() => IsBusy = false); }
    }

    public void Stop()
    {
        if (_stopped) return;
        _stopped = true;
        _scanState.Updated -= OnScanUpdated;
        if (Session is not null) Session.PropertyChanged -= OnSessionChanged;
        _lifetime.Cancel();
        ScanCommand.Cancel();
    }

    public async Task StopAsync()
    {
        Stop();
        if (ScanCommand.ExecutionTask is { } task) await task;
    }

    private void OnScanUpdated(object? sender, WifiScanSnapshot snapshot) =>
        Dispatcher.UIThread.Post(() => { if (!_stopped) ApplySnapshot(snapshot); });

    private void ApplySnapshot(WifiScanSnapshot snapshot)
    {
        if (snapshot.Version <= _snapshotVersion) return;
        _snapshotVersion = snapshot.Version;
        _lastAttemptFailed = false;
        var seen = snapshot.AccessPoints.Select(ap => ap.Bssid).ToHashSet(StringComparer.OrdinalIgnoreCase);
        foreach (var bssid in _rows.Keys.Where(key => !seen.Contains(key)).ToArray()) _rows.Remove(bssid);
        foreach (var ap in snapshot.AccessPoints)
        {
            if (_rows.TryGetValue(ap.Bssid, out var row)) row.Update(ap);
            else _rows.Add(ap.Bssid, new AccessPointRowViewModel(ap));
        }
        ApplyFilter();
        OnPropertyChanged(nameof(TotalCount));
        OnPropertyChanged(nameof(Ghz24Count));
        OnPropertyChanged(nameof(Ghz5Count));
        OnPropertyChanged(nameof(Ghz6Count));
        SetError(null);
        LastScanText = $"Последнее сканирование: {snapshot.CompletedAt.ToLocalTime():HH:mm:ss}";
        StatusText = TotalCount == 0 ? "Сканирование завершено. Точки доступа не обнаружены." : $"Обнаружено BSS: {TotalCount}";
        NotifyScanPresentation();
    }

    private void ApplyFilter()
    {
        var band = SelectedBandIndex switch { 1 => WifiBand.Ghz2_4, 2 => WifiBand.Ghz5, 3 => WifiBand.Ghz6, _ => (WifiBand?)null };
        var query = SearchText.Trim();
        var filtered = _rows.Values.Where(r => (band is null || r.AccessPoint.Band == band) &&
            (query.Length == 0 || r.Ssid.Contains(query, StringComparison.OrdinalIgnoreCase) || r.Bssid.Contains(query, StringComparison.OrdinalIgnoreCase)));
        var target = (StrongestFirst ? filtered.OrderByDescending(r => r.RssiDbm) : filtered.OrderBy(r => r.RssiDbm))
            .ThenBy(r => r.Bssid).ToArray();
        if (SelectedAccessPoint is not null && !target.Contains(SelectedAccessPoint)) SelectedAccessPoint = null;
        SynchronizeRows(AccessPoints, target);
        OnPropertyChanged(nameof(IsEmpty));
        OnPropertyChanged(nameof(EmptyText));
    }

    private void NotifyScanPresentation()
    {
        foreach (var name in new[] { nameof(HasSnapshot), nameof(ShowScanStatus), nameof(AreResultsPrevious), nameof(ResultCaption), nameof(EmptyText) }) OnPropertyChanged(name);
    }

    private static string FormatAdapterState(WifiAdapterState state) => state switch
    {
        WifiAdapterState.Connected => "подключён", WifiAdapterState.Disconnected => "не подключён",
        WifiAdapterState.NotReady => "отключён / не готов", _ => "изменение состояния"
    };
}
