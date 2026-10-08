using System.Globalization;
using Avalonia.Threading;
using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;
using Serilog;
using WirelessSecurityAnalyzer.Core.Analysis;
using WirelessSecurityAnalyzer.Core.Common;
using WirelessSecurityAnalyzer.Core.Interfaces;
using WirelessSecurityAnalyzer.Core.Models;

namespace WirelessSecurityAnalyzer.App.ViewModels;

public sealed partial class ChannelsViewModel : ViewModelBase
{
    private static readonly CultureInfo Russian = CultureInfo.GetCultureInfo("ru-RU");
    private readonly IChannelAnalyzer _analyzer;
    private readonly IWifiScanState _scanState;
    private readonly IWifiScanner _scanner;
    private readonly ChannelAnalysisOptions _options;
    private readonly ISystemSettingsService _settings;
    private readonly ILogger _logger;
    private readonly CancellationTokenSource _lifetime = new();
    private WifiScanSnapshot? _scanSnapshot;
    private long _sourceVersion;
    private bool _chooseDefaultBand = true, _settingDefaultBand, _stopped;
    private bool _hasLoggedRecommendation;
    private (WifiBand Band, int? Channel) _loggedRecommendation;

    public ChannelsViewModel(IChannelAnalyzer analyzer, IWifiScanState scanState, IWifiScanner scanner,
        ChannelAnalysisOptions options, ISystemSettingsService settings, ILogger logger)
    {
        _analyzer = analyzer;
        _scanState = scanState;
        _scanner = scanner;
        _options = options;
        _settings = settings;
        _logger = logger;
        _scanState.Updated += OnScanUpdated;
        _scanState.Failed += OnScanFailed;
        if (_scanState.Current is { } snapshot) ApplySnapshot(snapshot);
        if (_scanState.LastFailure is { } failure) ApplyFailure(failure);
    }

    public IReadOnlyList<string> Bands { get; } = ["2,4 ГГц", "5 ГГц", "6 ГГц"];
    [ObservableProperty] private int _selectedBandIndex;
    [ObservableProperty] private bool _isBusy;
    [ObservableProperty] private bool _hasError;
    [ObservableProperty] private bool _isLocationPermissionRequired;
    [ObservableProperty] private string _errorMessage = string.Empty;
    [ObservableProperty] private string _statusText = "Сначала выполните сканирование Wi-Fi эфира.";

    public WifiBand SelectedBand => SelectedBandIndex switch { 1 => WifiBand.Ghz5, 2 => WifiBand.Ghz6, _ => WifiBand.Ghz2_4 };
    public string SelectedBandText => Bands[Math.Clamp(SelectedBandIndex, 0, 2)];
    public ChannelAnalysisSnapshot? Analysis { get; private set; }
    public IReadOnlyList<ChannelRowViewModel> Channels { get; private set; } = [];
    public IReadOnlyList<ChannelSpectrumCurve> Spectrum => Analysis?.Spectrum ?? Array.Empty<ChannelSpectrumCurve>();
    public bool HasAnalysis => Spectrum.Count > 0;
    public bool HasChannelRows => HasAnalysis && Channels.Count > 0;
    public int BssCount => Spectrum.Count;
    public string SnapshotText => _scanSnapshot is null ? "Снимок ещё не получен" :
        "Снимок: " + _scanSnapshot.CompletedAt.ToLocalTime().ToString("dd.MM.yyyy HH:mm:ss", Russian);
    public string ModelWidthText => "Ширина канала: " + _options.DefaultChannelWidthMhz.ToString("0.#", Russian) + " МГц (модель)";
    public string RecommendationText => Analysis?.RecommendedChannel is { } channel
        ? $"Рекомендуемый по текущей оценке: канал {channel}" : "Рекомендация недоступна";
    public string RecommendedScoreText => Analysis?.Channels.FirstOrDefault(r => r.IsRecommended) is { } row
        ? "Оценка: " + row.LoadScorePercent.ToString("0.0", Russian) + "%" : string.Empty;
    public string EmptyText => _scanSnapshot is null ? "Сначала выполните сканирование Wi-Fi эфира." :
        $"В диапазоне {SelectedBandText} точки доступа не обнаружены.";
    public bool HasDataNotes => Analysis is { IgnoredBssCount: > 0 } or { DuplicateBssCount: > 0 } or { InvalidCandidateCount: > 0 };
    public string DataNotesText => Analysis is { } a
        ? $"Пропущено некорректных BSS: {a.IgnoredBssCount}; объединено дубликатов BSSID: {a.DuplicateBssCount}; недопустимых кандидатов: {a.InvalidCandidateCount}."
        : string.Empty;

    partial void OnSelectedBandIndexChanged(int value)
    {
        if (_settingDefaultBand) return;
        _chooseDefaultBand = false;
        Recalculate();
    }

    private bool CanRefreshAnalysis() => !_stopped;

    [RelayCommand(CanExecute = nameof(CanRefreshAnalysis), IncludeCancelCommand = true)]
    private async Task RefreshAnalysisAsync(CancellationToken cancellationToken)
    {
        using var linked = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken, _lifetime.Token);
        IsBusy = true;
        StatusText = "Обновление общего снимка Wi-Fi…";
        try
        {
            await _scanner.ScanAsync(linked.Token).ConfigureAwait(false);
            await Dispatcher.UIThread.InvokeAsync(() =>
            {
                if (!_stopped && _scanState.Current is { } snapshot) ApplySnapshot(snapshot);
            });
        }
        catch (OperationCanceledException) when (linked.IsCancellationRequested)
        {
            await Dispatcher.UIThread.InvokeAsync(() => StatusText = "Обновление отменено. Последний анализ сохранён.");
        }
        catch (Exception exception)
        {
            _logger.Error(exception, "Channel view scan failed");
            await Dispatcher.UIThread.InvokeAsync(() =>
            {
                if (_stopped) return;
                // Another queued scan may already have succeeded. Do not overwrite it with an older failure.
                if (_scanState.LastFailure is { } failure) ApplyFailure(failure);
                else if (_scanState.Current is { } snapshot) ApplySnapshot(snapshot);
                else ShowError(exception);
            });
        }
        finally { await Dispatcher.UIThread.InvokeAsync(() => IsBusy = false); }
    }

    [RelayCommand]
    private void OpenLocationSettings()
    {
        try { _settings.OpenLocationSettings(); }
        catch (Exception exception) { _logger.Error(exception, "Opening location settings failed"); ShowError(exception); }
    }

    public void Stop()
    {
        if (_stopped) return;
        _stopped = true;
        _scanState.Updated -= OnScanUpdated;
        _scanState.Failed -= OnScanFailed;
        _lifetime.Cancel();
        RefreshAnalysisCommand.Cancel();
        RefreshAnalysisCommand.NotifyCanExecuteChanged();
    }

    public async Task StopAsync()
    {
        Stop();
        if (RefreshAnalysisCommand.ExecutionTask is { } task) await task;
    }

    private void OnScanUpdated(object? sender, WifiScanSnapshot snapshot) =>
        Dispatcher.UIThread.Post(() => { if (!_stopped) ApplySnapshot(snapshot); });
    private void OnScanFailed(object? sender, WifiScanFailure failure) =>
        Dispatcher.UIThread.Post(() => { if (!_stopped) ApplyFailure(failure); });

    private void ApplySnapshot(WifiScanSnapshot snapshot)
    {
        if (snapshot.Version <= _sourceVersion) return;
        _sourceVersion = snapshot.Version;
        _scanSnapshot = snapshot;
        HasError = false;
        IsLocationPermissionRequired = false;
        ErrorMessage = string.Empty;
        if (_chooseDefaultBand)
        {
            var available = snapshot.AccessPoints.Select(ap => WifiChannelHelper.FromFrequency(ap.FrequencyMhz).Band).ToHashSet();
            var index = Array.FindIndex(new[] { WifiBand.Ghz2_4, WifiBand.Ghz5, WifiBand.Ghz6 }, available.Contains);
            if (index >= 0)
            {
                _chooseDefaultBand = false;
                _settingDefaultBand = true;
                SelectedBandIndex = index;
                _settingDefaultBand = false;
            }
        }
        Recalculate();
    }

    private void ApplyFailure(WifiScanFailure failure)
    {
        if (failure.Version <= _sourceVersion) return;
        _sourceVersion = failure.Version;
        ShowError(failure.Error);
    }

    private void Recalculate()
    {
        try
        {
            Analysis = _scanSnapshot is null ? null : _analyzer.Analyze(_scanSnapshot.AccessPoints, SelectedBand, _options);
            Channels = Analysis is null ? [] : Array.AsReadOnly(Analysis.Channels.Select(r => new ChannelRowViewModel(r)).ToArray());
            StatusText = !HasAnalysis ? EmptyText : Channels.Count == 0 ? "Для диапазона не настроены каналы-кандидаты." :
                $"BSS в диапазоне: {BssCount} · каналов-кандидатов: {Channels.Count}";
            if (Analysis is { } a)
            {
                _logger.Debug("Channel analysis: band {Band}, snapshot BSS {TotalBssCount}, valid band BSS {BandBssCount}, candidates {CandidateCount}, recommendation {Channel}, score {Score}",
                    a.Band, _scanSnapshot!.AccessPoints.Count, BssCount, Channels.Count, a.RecommendedChannel,
                    a.Channels.FirstOrDefault(r => r.IsRecommended)?.LoadScorePercent);
                if (!_hasLoggedRecommendation || _loggedRecommendation != (a.Band, a.RecommendedChannel))
                {
                    _logger.Information("Channel recommendation: band {Band}, BSS {BssCount}, candidates {CandidateCount}, channel {Channel}, score {Score}",
                        a.Band, BssCount, Channels.Count, a.RecommendedChannel, a.Channels.FirstOrDefault(r => r.IsRecommended)?.LoadScorePercent);
                    _loggedRecommendation = (a.Band, a.RecommendedChannel);
                    _hasLoggedRecommendation = true;
                }
                if (a.IgnoredBssCount > 0 || a.InvalidCandidateCount > 0)
                    _logger.Warning("Channel analysis skipped {InvalidBssCount} invalid BSS and {InvalidCandidateCount} invalid candidates from snapshot {Version}",
                        a.IgnoredBssCount, a.InvalidCandidateCount, _scanSnapshot!.Version);
            }
        }
        catch (Exception exception)
        {
            Analysis = null;
            Channels = [];
            _logger.Error(exception, "Channel analysis failed for band {Band}", SelectedBand);
            ShowError(exception);
        }
        foreach (var name in new[] { nameof(SelectedBand), nameof(SelectedBandText), nameof(Analysis), nameof(Channels),
            nameof(Spectrum), nameof(HasAnalysis), nameof(HasChannelRows), nameof(BssCount), nameof(SnapshotText),
            nameof(RecommendationText), nameof(RecommendedScoreText), nameof(EmptyText), nameof(HasDataNotes), nameof(DataNotesText) }) OnPropertyChanged(name);
    }

    private void ShowError(Exception exception)
    {
        HasError = true;
        IsLocationPermissionRequired = exception is WifiException { Kind: WifiErrorKind.AccessDenied };
        ErrorMessage = exception is WifiException wifi ? WifiErrorPresenter.GetMessage(wifi) :
            "Не удалось обновить анализ каналов. Подробности сохранены в локальном журнале.";
        StatusText = "Операция не выполнена. Последний успешный снимок сохранён.";
    }
}
