using System.Collections.ObjectModel;
using Avalonia.Threading;
using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;
using Serilog;
using WirelessSecurityAnalyzer.Core.Common;
using WirelessSecurityAnalyzer.Core.Interfaces;
using WirelessSecurityAnalyzer.Core.Models;

namespace WirelessSecurityAnalyzer.App.ViewModels;

public sealed partial class AccessPointsViewModel : ViewModelBase
{
    private readonly IWifiScanner _scanner;
    private readonly IWifiAdapterService _adapterService;
    private readonly ISystemSettingsService _settings;
    private readonly ILogger _logger;
    private readonly Dictionary<string, AccessPointRowViewModel> _rows = new(StringComparer.OrdinalIgnoreCase);
    private readonly CancellationTokenSource _lifetime = new();

    public AccessPointsViewModel(IWifiScanner scanner, IWifiAdapterService adapterService, ISystemSettingsService settings, ILogger logger)
    {
        _scanner = scanner;
        _adapterService = adapterService;
        _settings = settings;
        _logger = logger;
    }

    public ObservableCollection<AccessPointRowViewModel> AccessPoints { get; } = [];
    public IReadOnlyList<string> BandFilters { get; } = ["Все диапазоны", "2,4 ГГц", "5 ГГц", "6 ГГц"];
    public int TotalCount => _rows.Count;
    public int Ghz24Count => _rows.Values.Count(r => r.AccessPoint.Band == WifiBand.Ghz2_4);
    public int Ghz5Count => _rows.Values.Count(r => r.AccessPoint.Band == WifiBand.Ghz5);
    public int Ghz6Count => _rows.Values.Count(r => r.AccessPoint.Band == WifiBand.Ghz6);
    public bool IsEmpty => AccessPoints.Count == 0;

    [ObservableProperty] private string _searchText = string.Empty;
    [ObservableProperty] private int _selectedBandIndex;
    [ObservableProperty] private bool _strongestFirst = true;
    [ObservableProperty] private bool _isBusy;
    [ObservableProperty] private string _statusText = "Нажмите «Сканировать», чтобы получить реальные данные Wi-Fi.";
    [ObservableProperty] private string _adapterText = "Проверка Wi-Fi адаптеров…";
    [ObservableProperty] private string _errorMessage = string.Empty;
    [ObservableProperty] private bool _hasError;
    [ObservableProperty] private bool _isLocationPermissionRequired;
    [ObservableProperty] private string _lastScanText = "Сканирование ещё не выполнялось";

    partial void OnSearchTextChanged(string value) => ApplyFilter();
    partial void OnSelectedBandIndexChanged(int value) => ApplyFilter();
    partial void OnStrongestFirstChanged(bool value) => ApplyFilter();

    public async Task InitializeAsync()
    {
        try
        {
            var adapters = await _adapterService.GetAdaptersAsync(_lifetime.Token).ConfigureAwait(false);
            await Dispatcher.UIThread.InvokeAsync(() =>
            {
                AdapterText = adapters.Count == 0 ? "Wi-Fi адаптер не обнаружен" :
                    string.Join(" • ", adapters.Select(a => $"{a.Description} ({FormatAdapterState(a.State)})"));
                if (adapters.Count == 0) ShowError(new WifiException(WifiErrorKind.NoAdapter, "No adapter."));
            });
        }
        catch (OperationCanceledException) when (_lifetime.IsCancellationRequested) { }
        catch (Exception exception)
        {
            _logger.Error(exception, "Adapter detection failed");
            await Dispatcher.UIThread.InvokeAsync(() => { AdapterText = "Адаптер недоступен"; ShowError(exception); });
        }
    }

    [RelayCommand(IncludeCancelCommand = true)]
    private async Task ScanAsync(CancellationToken cancellationToken)
    {
        using var linked = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken, _lifetime.Token);
        IsBusy = true;
        HasError = false;
        IsLocationPermissionRequired = false;
        ErrorMessage = string.Empty;
        StatusText = "Сканирование эфира…";
        try
        {
            var results = await _scanner.ScanAsync(linked.Token).ConfigureAwait(false);
            await Dispatcher.UIThread.InvokeAsync(() =>
            {
                var seen = results.Select(ap => ap.Bssid).ToHashSet(StringComparer.OrdinalIgnoreCase);
                foreach (var bssid in _rows.Keys.Where(key => !seen.Contains(key)).ToArray()) _rows.Remove(bssid);
                foreach (var ap in results)
                {
                    if (_rows.TryGetValue(ap.Bssid, out var row)) row.Update(ap);
                    else _rows.Add(ap.Bssid, new AccessPointRowViewModel(ap));
                }
                ApplyFilter();
                OnPropertyChanged(nameof(TotalCount));
                OnPropertyChanged(nameof(Ghz24Count));
                OnPropertyChanged(nameof(Ghz5Count));
                OnPropertyChanged(nameof(Ghz6Count));
                LastScanText = $"Последнее сканирование: {DateTimeOffset.Now:HH:mm:ss}";
                StatusText = results.Count == 0 ? "Сканирование завершено. Точки доступа не обнаружены." : $"Обнаружено BSS: {TotalCount}";
            });
        }
        catch (OperationCanceledException) when (linked.IsCancellationRequested)
        {
            await Dispatcher.UIThread.InvokeAsync(() => StatusText = "Сканирование отменено. Последние результаты сохранены.");
        }
        catch (Exception exception)
        {
            _logger.Error(exception, "Wi-Fi scan failed");
            await Dispatcher.UIThread.InvokeAsync(() => ShowError(exception));
        }
        finally { await Dispatcher.UIThread.InvokeAsync(() => IsBusy = false); }
    }

    [RelayCommand]
    private void OpenLocationSettings()
    {
        try { _settings.OpenLocationSettings(); }
        catch (Exception exception)
        {
            _logger.Error(exception, "Opening location settings failed");
            ShowError(exception);
        }
    }

    public void Stop() { _lifetime.Cancel(); ScanCommand.Cancel(); }

    private void ShowError(Exception exception)
    {
        HasError = true;
        IsLocationPermissionRequired = exception is WifiException { Kind: WifiErrorKind.AccessDenied };
        ErrorMessage = exception is WifiException wifi ? WifiErrorPresenter.GetMessage(wifi) :
            "Не удалось выполнить операцию. Подробности сохранены в локальном журнале.";
        StatusText = "Операция не выполнена. Последние результаты сохранены.";
    }

    private void ApplyFilter()
    {
        var band = SelectedBandIndex switch { 1 => WifiBand.Ghz2_4, 2 => WifiBand.Ghz5, 3 => WifiBand.Ghz6, _ => (WifiBand?)null };
        var query = SearchText.Trim();
        var filtered = _rows.Values.Where(r => (band is null || r.AccessPoint.Band == band) &&
            (query.Length == 0 || r.Ssid.Contains(query, StringComparison.OrdinalIgnoreCase) || r.Bssid.Contains(query, StringComparison.OrdinalIgnoreCase)));
        var target = (StrongestFirst ? filtered.OrderByDescending(r => r.RssiDbm) : filtered.OrderBy(r => r.RssiDbm))
            .ThenBy(r => r.Bssid).ToArray();
        var visible = target.ToHashSet();
        for (var i = AccessPoints.Count - 1; i >= 0; i--)
            if (!visible.Contains(AccessPoints[i])) AccessPoints.RemoveAt(i);
        for (var i = 0; i < target.Length; i++)
        {
            if (i < AccessPoints.Count && ReferenceEquals(AccessPoints[i], target[i])) continue;
            var oldIndex = AccessPoints.IndexOf(target[i]);
            if (oldIndex >= 0) AccessPoints.Move(oldIndex, i);
            else AccessPoints.Insert(i, target[i]);
        }
        OnPropertyChanged(nameof(IsEmpty));
    }

    private static string FormatAdapterState(WifiAdapterState state) => state switch
    {
        WifiAdapterState.Connected => "подключён", WifiAdapterState.Disconnected => "не подключён",
        WifiAdapterState.NotReady => "отключён / не готов", _ => "изменение состояния"
    };
}
