using Serilog;
using WirelessSecurityAnalyzer.Core.Interfaces;
using WirelessSecurityAnalyzer.Core.Models;
using WirelessSecurityAnalyzer.Core.Network;

namespace WirelessSecurityAnalyzer.Infrastructure.Windows.Network;

/// <summary>Owns manual discovery and a single scan/delay monitoring loop, with session state.</summary>
public sealed class DeviceMonitorService(IDeviceDiscoveryService discovery, ILogger logger, TimeProvider? timeProvider = null)
    : IDeviceMonitorService, IDisposable
{
    private readonly TimeProvider _clock = timeProvider ?? TimeProvider.System;
    private readonly SemaphoreSlim _lifecycle = new(1, 1);
    private readonly object _dataGate = new();
    private readonly DeviceStateTracker _tracker = new();
    private DeviceMonitorSnapshot _snapshot = new(0, null, Array.AsReadOnly(Array.Empty<NetworkDevice>()),
        false, false, TimeSpan.FromSeconds(30), null, null, null, null);
    private CancellationTokenSource? _cancellation;
    private Task _worker = Task.CompletedTask;
    private bool _disposed;

    public DeviceMonitorSnapshot Current { get { lock (_dataGate) return _snapshot; } }
    public event EventHandler<DeviceMonitorSnapshot>? Updated;

    public async Task DiscoverOnceAsync(LocalNetworkInfo network, DeviceDiscoveryOptions options, CancellationToken cancellationToken = default)
    {
        Task worker;
        await _lifecycle.WaitAsync(cancellationToken).ConfigureAwait(false);
        try
        {
            Prepare(network, options, false, TimeSpan.FromSeconds(30), cancellationToken);
            worker = _worker = Task.Run(() => RunAsync(network, options, false, cancellationToken: _cancellation!.Token), CancellationToken.None);
        }
        finally { _lifecycle.Release(); }
        await worker.ConfigureAwait(false);
    }

    public async Task StartAsync(LocalNetworkInfo network, DeviceDiscoveryOptions options, TimeSpan? interval = null,
        CancellationToken cancellationToken = default)
    {
        var period = interval ?? TimeSpan.FromSeconds(30);
        if (period < TimeSpan.FromSeconds(10) || period > TimeSpan.FromSeconds(120)) throw new ArgumentOutOfRangeException(nameof(interval));
        await _lifecycle.WaitAsync(cancellationToken).ConfigureAwait(false);
        try
        {
            Prepare(network, options, true, period, cancellationToken);
            _worker = Task.Run(() => RunAsync(network, options, true, period, _cancellation!.Token), CancellationToken.None);
            logger.Information("Device monitoring started; interval {IntervalSeconds}s", period.TotalSeconds);
        }
        finally { _lifecycle.Release(); }
    }

    private void Prepare(LocalNetworkInfo network, DeviceDiscoveryOptions options, bool monitoring, TimeSpan interval, CancellationToken token)
    {
        ObjectDisposedException.ThrowIf(_disposed, this);
        token.ThrowIfCancellationRequested();
        options.Validate();
        network.Subnet.EnsureSweepAllowed(options.MaxAutoHostCount);
        if (!_worker.IsCompleted || Current.IsMonitoring || Current.IsDiscovering)
            throw new NetworkDiscoveryException(NetworkDiscoveryError.Busy, "Another discovery operation is running.");
        _cancellation?.Dispose();
        _cancellation = CancellationTokenSource.CreateLinkedTokenSource(token);
        var changed = Current.Network is { } old && !old.HasSameContext(network);
        lock (_dataGate) _tracker.SetContext(network);
        if (changed) logger.Information("Local network context changed to {InterfaceId} {Subnet}/{Prefix}; session history reset", network.InterfaceId, network.NetworkAddress, network.PrefixLength);
        logger.Information("Selected discovery interface {Name} ({InterfaceId}), local IP {Ip}, subnet {Subnet}/{Prefix}", network.Name, network.InterfaceId, network.LocalIpv4, network.NetworkAddress, network.PrefixLength);
        Change(s => s with { Network = network, IsMonitoring = monitoring, IsDiscovering = true,
            Interval = interval, Progress = null, Error = null, Warning = null,
            Devices = changed ? Array.AsReadOnly(Array.Empty<NetworkDevice>()) : s.Devices,
            LastCompletedAt = changed ? null : s.LastCompletedAt });
    }

    private async Task RunAsync(LocalNetworkInfo network, DeviceDiscoveryOptions options, bool monitoring,
        TimeSpan? interval = null, CancellationToken cancellationToken = default)
    {
        try
        {
            do
            {
                cancellationToken.ThrowIfCancellationRequested();
                Change(s => s with { IsDiscovering = true, Progress = null, Error = null });
                try
                {
                    var result = await discovery.DiscoverAsync(network, options, cancellationToken,
                        new InlineProgress(p => Change(s => s with { Progress = p }))).ConfigureAwait(false);
                    cancellationToken.ThrowIfCancellationRequested();
                    Change(s => s with { Devices = _tracker.Apply(result, options.OfflineAfterMissedScans),
                        IsDiscovering = false, LastCompletedAt = result.CompletedAt, Warning = result.Warning, Error = null });
                }
                catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested) { throw; }
                catch (Exception exception)
                {
                    var error = exception as NetworkDiscoveryException ?? new NetworkDiscoveryException(NetworkDiscoveryError.Unexpected, "Device discovery failed.", exception);
                    logger.Warning(exception, "Device discovery cycle failed: {Kind}", error.Kind);
                    Change(s => s with { IsDiscovering = false, Error = error });
                    if (!monitoring || error.Kind is not (NetworkDiscoveryError.NeighborTableFailed or NetworkDiscoveryError.ProbeFailed)) break;
                }
                if (monitoring)
                    await Task.Delay(interval!.Value, _clock, cancellationToken).ConfigureAwait(false);
            } while (monitoring);
        }
        catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested) { }
        finally
        {
            Change(s => s with { IsMonitoring = false, IsDiscovering = false, Progress = null });
            logger.Information("Device {Operation} stopped; last successful results retained", monitoring ? "monitoring" : "manual discovery");
        }
    }

    public async Task StopAsync()
    {
        await _lifecycle.WaitAsync().ConfigureAwait(false);
        try
        {
            _cancellation?.Cancel();
            await _worker.ConfigureAwait(false);
            _cancellation?.Dispose();
            _cancellation = null;
        }
        finally { _lifecycle.Release(); }
    }

    private void Change(Func<DeviceMonitorSnapshot, DeviceMonitorSnapshot> update)
    {
        DeviceMonitorSnapshot snapshot;
        lock (_dataGate) { _snapshot = snapshot = update(_snapshot) with { Version = _snapshot.Version + 1 }; }
        if (Updated is not { } handlers) return;
        foreach (EventHandler<DeviceMonitorSnapshot> handler in handlers.GetInvocationList())
            try { handler(this, snapshot); }
            catch (Exception exception) { logger.Error(exception, "Device monitor subscriber failed"); }
    }

    public void Dispose()
    {
        if (_disposed) return;
        _disposed = true;
        _cancellation?.Cancel();
    }

    private sealed class InlineProgress(Action<DeviceDiscoveryProgress> report) : IProgress<DeviceDiscoveryProgress>
    {
        public void Report(DeviceDiscoveryProgress value) => report(value);
    }
}
