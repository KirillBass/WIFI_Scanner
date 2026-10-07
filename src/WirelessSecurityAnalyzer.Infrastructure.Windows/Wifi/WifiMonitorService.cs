using Serilog;
using WirelessSecurityAnalyzer.Core.Analysis;
using WirelessSecurityAnalyzer.Core.Common;
using WirelessSecurityAnalyzer.Core.Interfaces;
using WirelessSecurityAnalyzer.Core.Models;

namespace WirelessSecurityAnalyzer.Infrastructure.Windows.Wifi;

/// <summary>One cancellable scan/delay loop; no UI or native API dependencies.</summary>
public sealed class WifiMonitorService : IWifiMonitorService, IDisposable
{
    public const int MaximumTrackedBssids = 32;
    private readonly IWifiScanner _scanner;
    private readonly ILogger _logger;
    private readonly TimeProvider _clock;
    private readonly SemaphoreSlim _lifecycle = new(1, 1);
    private readonly object _dataGate = new();
    private readonly Dictionary<string, TrackedHistory> _histories = new(StringComparer.OrdinalIgnoreCase);
    private CancellationTokenSource? _cancellation;
    private Task _monitorTask = Task.CompletedTask;
    private string? _activeBssid;
    private bool _isMonitoring;
    private bool _disposed;
    private TimeSpan _interval = TimeSpan.FromSeconds(5);
    private long _version;
    private long _lastAccess;

    public WifiMonitorService(IWifiScanner scanner, ILogger logger, TimeProvider? timeProvider = null)
    {
        _scanner = scanner;
        _logger = logger;
        _clock = timeProvider ?? TimeProvider.System;
    }

    public bool IsMonitoring { get { lock (_dataGate) return _isMonitoring; } }
    public WifiMonitorSnapshot Current { get { lock (_dataGate) return SnapshotLocked(_activeBssid); } }
    public event EventHandler<WifiMonitorSnapshot>? Updated;

    public async Task StartAsync(string bssid, TimeSpan? interval = null, CancellationToken cancellationToken = default)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(bssid);
        var period = interval ?? TimeSpan.FromSeconds(5);
        if (period < TimeSpan.FromSeconds(5) || period > TimeSpan.FromSeconds(60))
            throw new ArgumentOutOfRangeException(nameof(interval), "Monitoring interval must be 5–60 seconds.");
        await _lifecycle.WaitAsync(cancellationToken).ConfigureAwait(false);
        try
        {
            ObjectDisposedException.ThrowIf(_disposed, this);
            cancellationToken.ThrowIfCancellationRequested();
            if (IsMonitoring) throw new InvalidOperationException("Monitoring is already running.");
            await _monitorTask.ConfigureAwait(false);
            _cancellation?.Dispose();
            _cancellation = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
            WifiMonitorSnapshot snapshot;
            lock (_dataGate)
            {
                _activeBssid = bssid.Trim().ToUpperInvariant();
                _interval = period;
                _isMonitoring = true;
                var history = GetOrCreateLocked(_activeBssid);
                history.Error = null;
                history.IsPresent = null;
                snapshot = ChangedSnapshotLocked(_activeBssid);
            }
            _logger.Information("Monitoring started for {Bssid}; interval {IntervalSeconds}s", _activeBssid, period.TotalSeconds);
            Publish(snapshot);
            var target = _activeBssid!;
            var token = _cancellation.Token;
            _monitorTask = Task.Run(() => RunAsync(target, period, token), CancellationToken.None);
        }
        finally { _lifecycle.Release(); }
    }

    public async Task StopAsync()
    {
        await _lifecycle.WaitAsync().ConfigureAwait(false);
        try
        {
            _cancellation?.Cancel();
            await _monitorTask.ConfigureAwait(false);
            _cancellation?.Dispose();
            _cancellation = null;
        }
        finally { _lifecycle.Release(); }
    }

    public WifiMonitorSnapshot GetHistory(string bssid)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(bssid);
        lock (_dataGate) return SnapshotLocked(bssid.Trim().ToUpperInvariant());
    }

    public void ClearHistory(string bssid)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(bssid);
        WifiMonitorSnapshot snapshot;
        lock (_dataGate)
        {
            var key = bssid.Trim().ToUpperInvariant();
            GetOrCreateLocked(key).History.Clear();
            snapshot = ChangedSnapshotLocked(key);
        }
        Publish(snapshot);
    }

    private async Task RunAsync(string bssid, TimeSpan interval, CancellationToken token)
    {
        try
        {
            while (true)
            {
                token.ThrowIfCancellationRequested();
                try
                {
                    var results = await _scanner.ScanAsync(token).ConfigureAwait(false);
                    token.ThrowIfCancellationRequested();
                    var accessPoint = results.FirstOrDefault(ap => string.Equals(ap.Bssid, bssid, StringComparison.OrdinalIgnoreCase));
                    WifiMonitorSnapshot snapshot;
                    bool? wasPresent;
                    lock (_dataGate)
                    {
                        var history = GetOrCreateLocked(bssid);
                        wasPresent = history.IsPresent;
                        history.IsPresent = accessPoint is not null;
                        history.Error = null;
                        if (accessPoint is not null)
                            history.History.Add(new SignalSample(_clock.GetUtcNow(), accessPoint.RssiDbm));
                        snapshot = ChangedSnapshotLocked(bssid);
                    }
                    if (accessPoint is null && wasPresent != false)
                        _logger.Warning("Monitored BSSID {Bssid} temporarily disappeared", bssid);
                    else if (accessPoint is not null && wasPresent == false)
                        _logger.Information("Monitored BSSID {Bssid} recovered", bssid);
                    Publish(snapshot);
                }
                catch (OperationCanceledException) when (token.IsCancellationRequested) { throw; }
                catch (Exception) when (token.IsCancellationRequested) { throw new OperationCanceledException(token); }
                catch (WifiException exception)
                {
                    var fatal = exception.Kind is not (WifiErrorKind.Timeout or WifiErrorKind.ScanFailed);
                    _logger.Warning(exception, "Monitoring scan failed for {Bssid}; fatal {Fatal}", bssid, fatal);
                    ReportError(bssid, exception);
                    if (fatal) break;
                }
                catch (Exception exception)
                {
                    _logger.Error(exception, "Unexpected monitoring error for {Bssid}", bssid);
                    ReportError(bssid, new WifiException(WifiErrorKind.ScanFailed, "Unexpected monitoring failure.", exception));
                    break;
                }
                // The delay begins only after the previous scan and publication have finished.
                await Task.Delay(interval, _clock, token).ConfigureAwait(false);
            }
        }
        catch (OperationCanceledException) when (token.IsCancellationRequested) { }
        finally
        {
            WifiMonitorSnapshot snapshot;
            lock (_dataGate)
            {
                _isMonitoring = false;
                snapshot = ChangedSnapshotLocked(bssid);
            }
            _logger.Information("Monitoring stopped for {Bssid}", bssid);
            Publish(snapshot);
        }
    }

    private void ReportError(string bssid, WifiException exception)
    {
        WifiMonitorSnapshot snapshot;
        lock (_dataGate)
        {
            GetOrCreateLocked(bssid).Error = exception;
            snapshot = ChangedSnapshotLocked(bssid);
        }
        Publish(snapshot);
    }

    private TrackedHistory GetOrCreateLocked(string bssid)
    {
        if (!_histories.TryGetValue(bssid, out var tracked))
        {
            if (_histories.Count >= MaximumTrackedBssids)
            {
                var oldest = _histories.Where(pair => !string.Equals(pair.Key, _activeBssid, StringComparison.OrdinalIgnoreCase))
                    .MinBy(pair => pair.Value.LastAccess);
                _histories.Remove(oldest.Key);
            }
            tracked = new TrackedHistory(new SignalHistory(bssid));
            _histories.Add(bssid, tracked);
        }
        tracked.LastAccess = ++_lastAccess;
        return tracked;
    }

    private WifiMonitorSnapshot SnapshotLocked(string? bssid)
    {
        var active = string.Equals(bssid, _activeBssid, StringComparison.OrdinalIgnoreCase);
        var tracked = bssid is not null && _histories.TryGetValue(bssid, out var history) ? history : null;
        var samples = tracked?.History.GetSamples() ?? Array.AsReadOnly(Array.Empty<SignalSample>());
        return new WifiMonitorSnapshot(_version, bssid, active && _isMonitoring, _interval,
            tracked?.IsPresent, samples, SignalStatisticsCalculator.Calculate(samples), tracked?.Error);
    }

    private WifiMonitorSnapshot ChangedSnapshotLocked(string bssid)
    {
        _version++;
        return SnapshotLocked(bssid);
    }

    private void Publish(WifiMonitorSnapshot snapshot)
    {
        if (Updated is not { } handlers) return;
        foreach (EventHandler<WifiMonitorSnapshot> handler in handlers.GetInvocationList())
            try { handler(this, snapshot); }
            catch (Exception exception) { _logger.Error(exception, "Monitoring subscriber failed"); }
    }

    public void Dispose()
    {
        if (_disposed) return;
        _disposed = true;
        // Normal window shutdown awaits StopAsync before the DI container is disposed.
        _cancellation?.Cancel();
    }

    private sealed class TrackedHistory(SignalHistory history)
    {
        public SignalHistory History { get; } = history;
        public bool? IsPresent { get; set; }
        public WifiException? Error { get; set; }
        public long LastAccess { get; set; }
    }
}
