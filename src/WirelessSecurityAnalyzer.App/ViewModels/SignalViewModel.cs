using System.Collections.ObjectModel;
using System.Globalization;
using Avalonia.Threading;
using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;
using Serilog;
using WirelessSecurityAnalyzer.Core.Common;
using WirelessSecurityAnalyzer.Core.Interfaces;
using WirelessSecurityAnalyzer.Core.Models;

namespace WirelessSecurityAnalyzer.App.ViewModels;

public sealed partial class SignalViewModel : ViewModelBase
{
    private readonly IWifiMonitorService _monitor;
    private readonly IWifiScanState _scanState;
    private readonly ISystemSettingsService _settings;
    private readonly ILogger _logger;
    private readonly CancellationTokenSource _lifetime = new();
    private readonly Dictionary<string, AccessPointRowViewModel> _choices = new(StringComparer.OrdinalIgnoreCase);
    private AccessPointRowViewModel? _selectedAccessPoint;
    private WifiMonitorSnapshot? _snapshot;
    private long _scanVersion;
    private bool _stopped;
    private static readonly CultureInfo Russian = CultureInfo.GetCultureInfo("ru-RU");

    public SignalViewModel(IWifiMonitorService monitor, IWifiScanState scanState,
        ISystemSettingsService settings, ILogger logger)
    {
        _monitor = monitor;
        _scanState = scanState;
        _settings = settings;
        _logger = logger;
        StartMonitoringCommand.PropertyChanged += (_, e) =>
        {
            if (e.PropertyName == nameof(IAsyncRelayCommand.IsRunning)) NotifyControls();
        };
        _scanState.Updated += OnScanUpdated;
        _monitor.Updated += OnMonitorUpdated;
        if (_scanState.Current is { } snapshot) ApplyScanSnapshot(snapshot);
    }

    public ObservableCollection<AccessPointRowViewModel> AccessPoints { get; } = [];
    public IReadOnlyList<int> IntervalOptions { get; } = [5, 10, 15, 30, 60];
    [ObservableProperty] private int _selectedIntervalSeconds = 5;
    [ObservableProperty] private bool _isMonitoring;
    [ObservableProperty] private bool _isStopping;
    [ObservableProperty] private string _statusText = "Сначала выполните сканирование Wi-Fi эфира.";
    [ObservableProperty] private string _errorMessage = string.Empty;
    [ObservableProperty] private bool _hasError;
    [ObservableProperty] private bool _isLocationPermissionRequired;

    public AccessPointRowViewModel? SelectedAccessPoint
    {
        get => _selectedAccessPoint;
        set
        {
            if (!CanChangeSelection && !ReferenceEquals(value, _selectedAccessPoint)) return;
            if (!SetProperty(ref _selectedAccessPoint, value)) return;
            _snapshot = value is null ? null : _monitor.GetHistory(value.Bssid);
            UpdatePresentation();
        }
    }

    public bool CanChangeSelection => !IsMonitoring && !IsStopping && !StartMonitoringCommand.IsRunning;
    public string SelectedSsid => SelectedAccessPoint?.Ssid ?? "—";
    public string SelectedBssid => SelectedAccessPoint?.Bssid ?? "—";
    public string SelectedChannel => SelectedAccessPoint?.Channel ?? "—";
    public string SelectedBand => SelectedAccessPoint?.Band ?? "—";
    public IReadOnlyList<SignalSample> Samples => _snapshot?.Samples ?? Array.Empty<SignalSample>();
    public SignalStatistics Statistics => _snapshot?.Statistics ?? SignalStatistics.Empty;
    public int SampleCount => Statistics.SampleCount;
    public bool HasSamples => SampleCount > 0;
    public string CurrentRssiText => _snapshot?.IsPresentInLastScan == false ? "—" : FormatRssi(Statistics.CurrentRssiDbm);
    public string AverageRssiText => Statistics.AverageRssiDbm is { } value ? value.ToString("0.0", Russian) + " dBm" : "—";
    public string MinimumRssiText => FormatRssi(Statistics.MinimumRssiDbm);
    public string MaximumRssiText => FormatRssi(Statistics.MaximumRssiDbm);
    public string LastSeenText => Statistics.LastSeen?.ToLocalTime().ToString("dd.MM.yyyy HH:mm:ss", Russian) ?? "Измерений ещё нет";
    public string SignalQualityText => _snapshot?.IsPresentInLastScan == false ? "Не обнаружена" : Statistics.CurrentRssiDbm switch
    {
        null => "Нет измерений", >= -50 => "Отличный", >= -60 => "Хороший", >= -70 => "Средний",
        >= -80 => "Слабый", _ => "Очень слабый"
    };

    partial void OnIsMonitoringChanged(bool value) => NotifyControls();
    partial void OnIsStoppingChanged(bool value) => NotifyControls();

    private bool CanStartMonitoring() => SelectedAccessPoint is not null && !IsMonitoring && !IsStopping && !_stopped;
    private bool CanStopMonitoring() => IsMonitoring && !IsStopping && !StartMonitoringCommand.IsRunning;
    private bool CanClearHistory() => SelectedAccessPoint is not null && !IsStopping && !StartMonitoringCommand.IsRunning;

    [RelayCommand(CanExecute = nameof(CanStartMonitoring))]
    private async Task StartMonitoringAsync()
    {
        if (SelectedAccessPoint is not { } selected) return;
        try
        {
            IsMonitoring = true;
            await _monitor.StartAsync(selected.Bssid, TimeSpan.FromSeconds(SelectedIntervalSeconds), _lifetime.Token);
            ApplyMonitorSnapshot(_monitor.Current);
        }
        catch (OperationCanceledException) when (_lifetime.IsCancellationRequested) { IsMonitoring = _monitor.IsMonitoring; }
        catch (Exception exception)
        {
            IsMonitoring = _monitor.IsMonitoring;
            ShowError(exception);
        }
    }

    [RelayCommand(CanExecute = nameof(CanStopMonitoring))]
    private async Task StopMonitoringAsync()
    {
        IsStopping = true;
        try
        {
            await _monitor.StopAsync();
            ApplyMonitorSnapshot(_monitor.Current);
        }
        finally { IsStopping = false; }
    }

    [RelayCommand(CanExecute = nameof(CanClearHistory))]
    private void ClearHistory()
    {
        if (SelectedAccessPoint is not { } selected) return;
        _monitor.ClearHistory(selected.Bssid);
        ApplyMonitorSnapshot(_monitor.GetHistory(selected.Bssid));
    }

    [RelayCommand]
    private void OpenLocationSettings()
    {
        try { _settings.OpenLocationSettings(); }
        catch (Exception exception) { ShowError(exception); }
    }

    public void Stop()
    {
        if (_stopped) return;
        _stopped = true;
        _scanState.Updated -= OnScanUpdated;
        _monitor.Updated -= OnMonitorUpdated;
        _lifetime.Cancel();
    }

    public async Task StopAsync()
    {
        Stop();
        if (StartMonitoringCommand.ExecutionTask is { } start) await start;
        await _monitor.StopAsync();
        if (StopMonitoringCommand.ExecutionTask is { } stop) await stop;
    }

    private void OnScanUpdated(object? sender, WifiScanSnapshot snapshot) =>
        Dispatcher.UIThread.Post(() => { if (!_stopped) ApplyScanSnapshot(snapshot); });

    private void OnMonitorUpdated(object? sender, WifiMonitorSnapshot snapshot) =>
        Dispatcher.UIThread.Post(() => { if (!_stopped) ApplyMonitorSnapshot(snapshot); });

    private void ApplyScanSnapshot(WifiScanSnapshot snapshot)
    {
        if (snapshot.Version <= _scanVersion) return;
        _scanVersion = snapshot.Version;
        var seen = snapshot.AccessPoints.Select(ap => ap.Bssid).ToHashSet(StringComparer.OrdinalIgnoreCase);
        foreach (var key in _choices.Keys.Where(key => !seen.Contains(key) &&
            !string.Equals(key, SelectedAccessPoint?.Bssid, StringComparison.OrdinalIgnoreCase)).ToArray()) _choices.Remove(key);
        foreach (var ap in snapshot.AccessPoints)
        {
            if (_choices.TryGetValue(ap.Bssid, out var row)) row.Update(ap);
            else _choices.Add(ap.Bssid, new AccessPointRowViewModel(ap));
        }
        var target = _choices.Values.OrderBy(row => row.Ssid).ThenBy(row => row.Bssid).ToArray();
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
        UpdatePresentation();
    }

    private void ApplyMonitorSnapshot(WifiMonitorSnapshot snapshot)
    {
        if (!string.Equals(snapshot.Bssid, SelectedAccessPoint?.Bssid, StringComparison.OrdinalIgnoreCase)) return;
        if (_snapshot is { } previous && snapshot.Version < previous.Version) return;
        _snapshot = snapshot;
        IsMonitoring = snapshot.IsMonitoring;
        UpdatePresentation();
    }

    private void UpdatePresentation()
    {
        HasError = _snapshot?.Error is not null;
        IsLocationPermissionRequired = _snapshot?.Error?.Kind == WifiErrorKind.AccessDenied;
        ErrorMessage = _snapshot?.Error is { } error ? WifiErrorPresenter.GetMessage(error) : string.Empty;
        StatusText = SelectedAccessPoint is null
            ? AccessPoints.Count == 0 ? "Сначала выполните сканирование Wi-Fi эфира." : "Выберите точку доступа для мониторинга."
            : HasError ? IsMonitoring ? "Ошибка сканирования. Мониторинг продолжится со следующей попытки." : "Мониторинг остановлен из-за ошибки."
            : _snapshot?.IsPresentInLastScan == false ? "Точка доступа не обнаружена в последнем сканировании. История сохранена."
            : IsMonitoring ? "Мониторинг активен" : "Мониторинг остановлен. Можно начать или продолжить измерения.";
        foreach (var name in new[] { nameof(SelectedSsid), nameof(SelectedBssid), nameof(SelectedChannel), nameof(SelectedBand),
            nameof(Samples), nameof(Statistics), nameof(SampleCount), nameof(HasSamples), nameof(CurrentRssiText), nameof(AverageRssiText),
            nameof(MinimumRssiText), nameof(MaximumRssiText), nameof(LastSeenText), nameof(SignalQualityText) }) OnPropertyChanged(name);
        NotifyControls();
    }

    private void NotifyControls()
    {
        OnPropertyChanged(nameof(CanChangeSelection));
        StartMonitoringCommand.NotifyCanExecuteChanged();
        StopMonitoringCommand.NotifyCanExecuteChanged();
        ClearHistoryCommand.NotifyCanExecuteChanged();
    }

    private void ShowError(Exception exception)
    {
        _logger.Error(exception, "Signal view operation failed");
        HasError = true;
        IsLocationPermissionRequired = exception is WifiException { Kind: WifiErrorKind.AccessDenied };
        ErrorMessage = exception is WifiException wifi ? WifiErrorPresenter.GetMessage(wifi) : "Не удалось выполнить операцию. Подробности сохранены в журнале.";
        StatusText = "Операция не выполнена. История сохранена.";
    }

    private static string FormatRssi(int? value) => value is { } rssi ? rssi.ToString(Russian) + " dBm" : "—";
}
