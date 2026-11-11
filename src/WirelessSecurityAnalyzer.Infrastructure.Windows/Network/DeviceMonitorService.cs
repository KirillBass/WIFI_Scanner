using System.Net;
using System.Threading.Channels;
using Serilog;
using WirelessSecurityAnalyzer.Core.Interfaces;
using WirelessSecurityAnalyzer.Core.Models;
using WirelessSecurityAnalyzer.Core.Network;

namespace WirelessSecurityAnalyzer.Infrastructure.Windows.Network;

/// <summary>Owns manual discovery and a single scan/delay monitoring loop, with session state.</summary>
public sealed class DeviceMonitorService(IDeviceDiscoveryService discovery, ILogger logger, TimeProvider? timeProvider = null,
    IDeviceIdentityResolver? identityResolver = null, INetworkSessionService? sessions = null)
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
    private CancellationTokenSource? _identityCancellation;
    private Task _identityWorker = Task.CompletedTask;
    private bool _disposed;
    private bool _sessionSubscribed;
    private bool _sessionWasReady;
    private Channel<byte>? _identitySignal;
    private readonly Dictionary<IPAddress, NetworkDevice> _identityPending = [];


    public DeviceMonitorSnapshot Current { get { lock (_dataGate) return _snapshot; } }
    public event EventHandler<DeviceMonitorSnapshot>? Updated;

    public async Task DiscoverOnceAsync(LocalNetworkInfo network, DeviceDiscoveryOptions options, CancellationToken cancellationToken = default)
    {
        Task worker;
        await _lifecycle.WaitAsync(cancellationToken).ConfigureAwait(false);
        try
        {
            EnsureIdle();
            await StopIdentityAsync().ConfigureAwait(false);
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
            EnsureIdle();
            await StopIdentityAsync().ConfigureAwait(false);
            Prepare(network, options, true, period, cancellationToken);
            _worker = Task.Run(() => RunAsync(network, options, true, period, _cancellation!.Token), CancellationToken.None);
            logger.Information("Device monitoring started; interval {IntervalSeconds}s", period.TotalSeconds);
        }
        finally { _lifecycle.Release(); }
    }

    public async Task RefreshIdentitiesAsync(LocalNetworkInfo network, CancellationToken cancellationToken = default)
    {
        Task worker;
        await _lifecycle.WaitAsync(cancellationToken).ConfigureAwait(false);
        try
        {
            EnsureIdle();
            if (Current.Network?.HasSameContext(network) != true || !Current.Devices.Any(d => d.State == DeviceState.Online))
                throw new NetworkDiscoveryException(NetworkDiscoveryError.ContextChanged, "Refresh discovery in the selected network first.");
            if (identityResolver is null) return;
            await StopIdentityAsync().ConfigureAwait(false);
            cancellationToken.ThrowIfCancellationRequested();
            identityResolver.InvalidateCache(network, Current.Devices);
            BeginIdentity(network, cancellationToken);
            worker = _identityWorker;
        }
        finally { _lifecycle.Release(); }
        await worker.ConfigureAwait(false);
    }

    private void Prepare(LocalNetworkInfo network, DeviceDiscoveryOptions options, bool monitoring, TimeSpan interval, CancellationToken token)
    {
        ObjectDisposedException.ThrowIf(_disposed, this);
        token.ThrowIfCancellationRequested();
        options.Validate();
        network.Subnet.EnsureSweepAllowed();
        if (!_worker.IsCompleted || Current.IsMonitoring || Current.IsDiscovering)
            throw new NetworkDiscoveryException(NetworkDiscoveryError.Busy, "Another discovery operation is running.");
        _cancellation?.Dispose();
        _cancellation = CancellationTokenSource.CreateLinkedTokenSource(token);
        if (sessions is not null && !_sessionSubscribed)
        { sessions.Updated += OnSessionChanged; _sessionSubscribed = true; }
        var session = sessions?.Current;
        _sessionWasReady = session?.IsReadyForAudit == true;
        var changed = Current.Network is { } old && !old.HasSameContext(network) ||
            Current.SessionId != (session?.SessionId ?? Guid.Empty);
        lock (_dataGate) { if (changed) _tracker.Clear(); _tracker.SetContext(network); }
        if (changed) logger.Information("Local network context changed to {InterfaceId} {Subnet}/{Prefix}; session history reset", network.InterfaceId, network.NetworkAddress, network.PrefixLength);
        logger.Information("Selected discovery interface {Name} ({InterfaceId}), local IP {Ip}, subnet {Subnet}/{Prefix}", network.Name, network.InterfaceId, network.LocalIpv4, network.NetworkAddress, network.PrefixLength);
        Change(s => s with { Network = network, IsMonitoring = monitoring, IsDiscovering = true,
            Interval = interval, Progress = null, Error = null, Warning = null,
            Devices = changed ? Array.AsReadOnly(Array.Empty<NetworkDevice>()) : s.Devices,
            LastCompletedAt = changed ? null : s.LastCompletedAt, RunId = Guid.NewGuid(), SessionId = session?.SessionId ?? Guid.Empty });
        if (sessions is not null && sessions.Current.SessionId != (session?.SessionId ?? Guid.Empty))
        {
            OnSessionChanged(sessions, sessions.Current);
            throw new NetworkDiscoveryException(NetworkDiscoveryError.ContextChanged, "Network session changed while preparing discovery.");
        }
    }

    private void EnsureIdle()
    {
        ObjectDisposedException.ThrowIf(_disposed, this);
        if (!_worker.IsCompleted || Current.IsMonitoring || Current.IsDiscovering)
            throw new NetworkDiscoveryException(NetworkDiscoveryError.Busy, "Another discovery operation is running.");
    }

    private async Task RunAsync(LocalNetworkInfo network, DeviceDiscoveryOptions options, bool monitoring,
        TimeSpan? interval = null, CancellationToken cancellationToken = default)
    {
        try
        {
            do
            {
                cancellationToken.ThrowIfCancellationRequested();
                await StopIdentityAsync().ConfigureAwait(false);
                cancellationToken.ThrowIfCancellationRequested();
                var runId = Guid.NewGuid();
                var sessionId = Current.SessionId;
                Change(s => s with { IsDiscovering = true, Progress = null, Error = null, RunId = runId });
                try
                {
                    if (discovery is IStreamingDeviceDiscoveryService streaming)
                    {
                        BeginStreamingIdentity(network, runId, sessionId, cancellationToken);
                        DeviceDiscoveryResult result;
                        try
                        {
                            result = await streaming.DiscoverStreamingAsync(network, options,
                                new(runId, sessionId, Current.Devices), update => OnDiscoveryEvent(network, options, update, cancellationToken),
                                cancellationToken).ConfigureAwait(false);
                        }
                        finally { _identitySignal?.Writer.TryComplete(); }
                        ChangeScoped(runId, sessionId, s => s with { IsDiscovering = false,
                            Progress = result.Progress, Warning = result.Warning, Error = null,
                            LastCompletedAt = result.IsCancelled ? s.LastCompletedAt : result.CompletedAt });
                        if (result.IsCancelled) break;
                    }
                    else
                    {
                        var result = await discovery.DiscoverAsync(network, options, cancellationToken,
                            new InlineProgress(p => Change(s => s with { Progress = p }))).ConfigureAwait(false);
                        cancellationToken.ThrowIfCancellationRequested();
                        Change(s => s with { Devices = _tracker.Apply(result, options.OfflineAfterMissedScans),
                            IsDiscovering = false, LastCompletedAt = result.CompletedAt, Warning = result.Warning, Error = null });
                        // The discovery snapshot is already published. Name lookups run independently
                        // of the scan/delay loop, and are replaced only at a completed discovery cycle.
                        if (identityResolver is not null)
                        {
                            await StopIdentityAsync().ConfigureAwait(false);
                            cancellationToken.ThrowIfCancellationRequested();
                            BeginIdentity(network, cancellationToken);
                        }
                    }
                }
                catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested) { throw; }
                catch (Exception exception)
                {
                    var error = exception as NetworkDiscoveryException ?? new NetworkDiscoveryException(NetworkDiscoveryError.Unexpected, "Device discovery failed.", exception);
                    logger.Warning(exception, "Device discovery cycle failed: {Kind}", error.Kind);
                    ChangeScoped(runId, sessionId, s => s with { IsDiscovering = false, Error = error });
                    if (!monitoring || error.Kind is not (NetworkDiscoveryError.NeighborTableFailed or NetworkDiscoveryError.ProbeFailed)) break;
                }
                if (monitoring)
                    await Task.Delay(interval!.Value, _clock, cancellationToken).ConfigureAwait(false);
            } while (monitoring);
        }
        catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
        {
            if (discovery is IStreamingDeviceDiscoveryService)
                Change(s => s.Network?.HasSameContext(network) == true && s.Progress?.Stage is not
                    (DeviceDiscoveryStage.Completed or DeviceDiscoveryStage.Cancelled or DeviceDiscoveryStage.Error)
                    ? s with { Progress = (s.Progress ?? new(DeviceDiscoveryStage.Cancelled, 0, checked((long)network.Subnet.UsableHostCount), 0))
                        with { Stage = DeviceDiscoveryStage.Cancelled, Active = 0 } } : s);
        }
        finally
        {
            Change(s => s with { IsMonitoring = false, IsDiscovering = false,
                Progress = discovery is IStreamingDeviceDiscoveryService ? s.Progress : null });
            logger.Information("Device {Operation} stopped; last successful results retained", monitoring ? "monitoring" : "manual discovery");
        }
    }

    public async Task StopAsync()
    {
        await _lifecycle.WaitAsync().ConfigureAwait(false);
        try
        {
            await StopWorkerAsync().ConfigureAwait(false);
        }
        finally { _lifecycle.Release(); }
    }

    public async Task ResetAsync()
    {
        await _lifecycle.WaitAsync().ConfigureAwait(false);
        try
        {
            await StopWorkerAsync().ConfigureAwait(false);
            lock (_dataGate) _tracker.Clear();
            Change(s => new(s.Version, null, Array.AsReadOnly(Array.Empty<NetworkDevice>()), false, false,
                s.Interval, null, null, null, null));
        }
        finally { _lifecycle.Release(); }
    }

    private async Task StopWorkerAsync()
    {
        _cancellation?.Cancel();
        await _worker.ConfigureAwait(false);
        await StopIdentityAsync().ConfigureAwait(false);
        _cancellation?.Dispose();
        _cancellation = null;
    }

    private void BeginIdentity(LocalNetworkInfo network, CancellationToken token)
    {
        _identityCancellation = CancellationTokenSource.CreateLinkedTokenSource(token);
        var identityToken = _identityCancellation.Token;
        var runId = Current.RunId;
        var sessionId = Current.SessionId;
        Change(s => s with { Devices = _tracker.SetResolving(true), IsResolvingIdentities = true });
        var devices = Current.Devices;
        _identityWorker = Task.Run(async () =>
        {
            try
            {
                await identityResolver!.EnrichAsync(network, devices, update => ChangeScoped(runId, sessionId, s =>
                    identityToken.IsCancellationRequested || s.Network?.HasSameContext(network) != true ? s :
                    s with { Devices = _tracker.Enrich(update.Device, update.Identity, update.IsComplete) }), identityToken).ConfigureAwait(false);
            }
            catch (OperationCanceledException) when (identityToken.IsCancellationRequested) { }
            catch (Exception exception) { logger.Warning(exception, "Device identity enrichment failed; discovery results retained"); }
            finally { ChangeScoped(runId, sessionId, s => s with { Devices = _tracker.SetResolving(false), IsResolvingIdentities = false }); }
        }, CancellationToken.None);
    }

    private async Task StopIdentityAsync()
    {
        _identityCancellation?.Cancel();
        await _identityWorker.ConfigureAwait(false);
        _identityCancellation?.Dispose();
        _identityCancellation = null;
        lock (_dataGate) { _identitySignal = null; _identityPending.Clear(); }
        Change(s => s.IsResolvingIdentities || s.Devices.Any(d => d.IsIdentityResolving)
            ? s with { Devices = _tracker.SetResolving(false), IsResolvingIdentities = false } : s);
    }

    private void OnDiscoveryEvent(LocalNetworkInfo network, DeviceDiscoveryOptions options, DeviceDiscoveryEvent update, CancellationToken token)
    {
        ChangeScoped(update.RunId, update.SessionId, s =>
        {
            if (!s.IsDiscovering) return s;
            if (update.Observation is { } observation && s.IsDiscovering)
            {
                var devices = _tracker.Observe(network, observation);
                var device = devices.First(d => d.IpAddress.Equals(observation.IpAddress));
                if (_identitySignal is not null && !token.IsCancellationRequested)
                {
                    // A late MAC upgrade replaces the pending item instead of duplicating work.
                    _identityPending[device.IpAddress] = device;
                    _identitySignal.Writer.TryWrite(0);
                    devices = _tracker.SetResolving(device, true);
                }
                return s with { Devices = devices, IsResolvingIdentities = s.IsResolvingIdentities ||
                    _identitySignal is not null && !token.IsCancellationRequested };
            }
            if (update.CheckedAddress is { } address && !token.IsCancellationRequested && s.Devices.Any(d => d.IpAddress.Equals(address)))
                return s with { Devices = _tracker.AddressChecked(address, update.HasReliableAbsence, options.OfflineAfterMissedScans) };
            return s with { Progress = update.Progress ?? s.Progress, Warning = update.Result?.Warning ?? s.Warning,
                Error = update.Error ?? s.Error };
        });
        if (update.Error?.Kind == NetworkDiscoveryError.ContextChanged && Current.RunId == update.RunId)
            _identityCancellation?.Cancel();
    }

    private void BeginStreamingIdentity(LocalNetworkInfo network, Guid runId, Guid sessionId, CancellationToken token)
    {
        if (identityResolver is null) return;
        _identityCancellation = CancellationTokenSource.CreateLinkedTokenSource(token);
        var identityToken = _identityCancellation.Token;
        var signal = Channel.CreateBounded<byte>(new BoundedChannelOptions(1)
        { SingleReader = true, FullMode = BoundedChannelFullMode.DropWrite });
        lock (_dataGate) { _identitySignal = signal; _identityPending.Clear(); }
        _identityWorker = Task.Run(async () =>
        {
            try
            {
                while (await signal.Reader.WaitToReadAsync(identityToken).ConfigureAwait(false))
                {
                    while (signal.Reader.TryRead(out _)) { }
                    while (true)
                    {
                        NetworkDevice[] batch;
                        lock (_dataGate)
                        {
                            batch = _identityPending.Values.Take(32).ToArray();
                            foreach (var device in batch) _identityPending.Remove(device.IpAddress);
                            // Existing identity cache uses the confirmed gateway MAC as a LAN witness.
                            var gateway = _snapshot.Devices.FirstOrDefault(d => d.IsGateway && d.State == DeviceState.Online);
                            if (batch.Length > 0 && gateway is not null && !batch.Any(d => d.IsGateway)) batch = [.. batch, gateway];
                        }
                        if (batch.Length == 0) break;
                        identityToken.ThrowIfCancellationRequested();
                        try
                        {
                            await identityResolver.EnrichAsync(network, batch, update => ChangeScoped(runId, sessionId,
                                s => identityToken.IsCancellationRequested ? s : s with
                                { Devices = _tracker.Enrich(update.Device, update.Identity, update.IsComplete) }), identityToken).ConfigureAwait(false);
                        }
                        catch (OperationCanceledException) when (identityToken.IsCancellationRequested) { throw; }
                        catch (Exception exception) { logger.Warning(exception, "Streaming device identity batch failed"); }
                        ChangeScoped(runId, sessionId, s =>
                        {
                            foreach (var device in batch) _tracker.SetResolving(device, false);
                            return s with { Devices = _tracker.Snapshot(), IsResolvingIdentities = _identityPending.Count > 0 };
                        });
                    }
                }
            }
            catch (OperationCanceledException) when (identityToken.IsCancellationRequested) { }
            finally { ChangeScoped(runId, sessionId, s => s with { Devices = _tracker.SetResolving(false), IsResolvingIdentities = false }); }
        }, CancellationToken.None);
    }

    private void OnSessionChanged(object? sender, NetworkSession session)
    {
        var current = Current;
        if (current.Network is null || current.SessionId == session.SessionId &&
            (!_sessionWasReady || session.IsReadyForAudit &&
                (session.Network is null || session.Network.InterfaceId != current.Network.InterfaceId || session.Network.HasSameContext(current.Network)))) return;
        // Invalidate the scope before signalling cancellation; even uncooperative callbacks are now obsolete.
        Change(s =>
        {
            _tracker.Clear();
            return s with { RunId = Guid.NewGuid(), SessionId = session.SessionId, Network = null, Devices = _tracker.Snapshot(),
                Progress = null, LastCompletedAt = null, Error = null, Warning = null, IsDiscovering = false,
                IsMonitoring = false, IsResolvingIdentities = false };
        });
        _cancellation?.Cancel();
        _identityCancellation?.Cancel();
        logger.Information("Device discovery invalidated by network session change to {SessionId}", session.SessionId);
    }

    private void ChangeScoped(Guid runId, Guid sessionId, Func<DeviceMonitorSnapshot, DeviceMonitorSnapshot> update) =>
        Change(s => s.RunId == runId && s.SessionId == sessionId && (sessions is null || sessions.Current.SessionId == sessionId) ? update(s) : s);

    private void Change(Func<DeviceMonitorSnapshot, DeviceMonitorSnapshot> update)
    {
        DeviceMonitorSnapshot snapshot;
        lock (_dataGate)
        {
            var next = update(_snapshot);
            if (ReferenceEquals(next, _snapshot) || next == _snapshot) return;
            _snapshot = snapshot = next with { Version = _snapshot.Version + 1 };
        }
        if (Updated is not { } handlers) return;
        foreach (EventHandler<DeviceMonitorSnapshot> handler in handlers.GetInvocationList())
            try { handler(this, snapshot); }
            catch (Exception exception) { logger.Error(exception, "Device monitor subscriber failed"); }
    }

    public void Dispose()
    {
        if (_disposed) return;
        _disposed = true;
        if (_sessionSubscribed) sessions!.Updated -= OnSessionChanged;
        _cancellation?.Cancel();
        _identityCancellation?.Cancel();
    }

    private sealed class InlineProgress(Action<DeviceDiscoveryProgress> report) : IProgress<DeviceDiscoveryProgress>
    {
        public void Report(DeviceDiscoveryProgress value) => report(value);
    }
}
