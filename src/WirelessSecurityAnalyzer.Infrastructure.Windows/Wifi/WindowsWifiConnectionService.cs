using Serilog;
using WirelessSecurityAnalyzer.Core.Common;
using WirelessSecurityAnalyzer.Core.Interfaces;
using WirelessSecurityAnalyzer.Core.Models;
using WirelessSecurityAnalyzer.Infrastructure.Windows.NativeWifi;
using WirelessSecurityAnalyzer.Infrastructure.Windows.Network.Identity;

namespace WirelessSecurityAnalyzer.Infrastructure.Windows.Wifi;

public sealed class WindowsWifiConnectionService(IWifiConnectionBackend backend, WifiProfileBuilder profiles,
    ILocalNetworkService networks, INetworkSessionService sessions, WifiOperationCoordinator coordinator,
    WifiConnectionOptions options, ILogger logger, IDeviceMonitorService? devices = null,
    IWifiMonitorService? signal = null, DeviceIdentityCache? identityCache = null, TimeProvider? timeProvider = null)
    : IWifiConnectionService, IDisposable
{
    private readonly TimeProvider _clock = timeProvider ?? TimeProvider.System;
    private readonly SemaphoreSlim _operations = new(1, 1);
    private readonly CancellationTokenSource _lifetime = new();
    private readonly object _tasks = new();
    private Task _pending = Task.CompletedTask;
    private Task? _initialization;
    private Task _watcher = Task.CompletedTask;

    public Task InitializeAsync(CancellationToken cancellationToken = default)
    {
        lock (_tasks) return _initialization ??= InitializeCoreAsync(cancellationToken);
    }
    private async Task InitializeCoreAsync(CancellationToken token)
    {
        options.Validate();
        using var linked = CancellationTokenSource.CreateLinkedTokenSource(token, _lifetime.Token);
        try
        {
            await _operations.WaitAsync(linked.Token).ConfigureAwait(false);
            try { await RefreshAsync(linked.Token).ConfigureAwait(false); }
            finally { _operations.Release(); }
        }
        catch (WifiException ex) when (ex.Kind == WifiErrorKind.UnsupportedPlatform) { return; }
        catch (OperationCanceledException) when (linked.IsCancellationRequested) { return; }
        catch (Exception ex) { logger.Debug("Initial Wi-Fi session unavailable: {ErrorType}", ex.GetType().Name); }
        _watcher = Task.Run(WatchAsync);
    }

    public Task<WifiConnectionResult> ConnectAsync(WifiConnectionRequest request, CancellationToken cancellationToken = default)
    {
        lock (_tasks)
        {
            if (_lifetime.IsCancellationRequested) { request.ClearCredentials(); return Task.FromResult(Result(WifiConnectionFailure.Cancelled, request)); }
            if (!_operations.Wait(0)) { request.ClearCredentials(); return Task.FromResult(Result(WifiConnectionFailure.Busy, request)); }
            var task = ConnectCoreAsync(request, cancellationToken);
            _pending = task;
            return task;
        }
    }

    private async Task<WifiConnectionResult> ConnectCoreAsync(WifiConnectionRequest request, CancellationToken token)
    {
        using var linked = CancellationTokenSource.CreateLinkedTokenSource(token, _lifetime.Token);
        var ownsWlan = false;
        var sessionId = Guid.Empty;
        var associated = false;
        try
        {
            options.Validate();
            profiles.Validate(request);
            linked.Token.ThrowIfCancellationRequested();
            sessionId = sessions.BeginConnection(request).SessionId;
            await StopSessionOperationsAsync().ConfigureAwait(false);
            await coordinator.Gate.WaitAsync(linked.Token).ConfigureAwait(false);
            ownsWlan = true;
            logger.Information("Wi-Fi connection start: SSID {Ssid}, selected BSSID {Bssid}, interface {Interface}, security {Security}",
                request.Ssid, request.Bssid, request.InterfaceId, request.SecurityInfo.Protocol);
            using var deadline = new CancellationTokenSource(options.ConnectionTimeout, _clock);
            using var connectToken = CancellationTokenSource.CreateLinkedTokenSource(linked.Token, deadline.Token);
            var xml = profiles.Build(request);
            Task<WifiConnectionInfo> connecting;
            try
            {
                connecting = backend.ConnectAsync(request.InterfaceId, xml, profiles.GetSsidBytes(request), options.ConnectionTimeout,
                    new StateProgress(state => sessions.SetState(sessionId, state)), connectToken.Token);
            }
            finally { xml = null!; request.ClearCredentials(); }
            WifiConnectionInfo connection;
            try { connection = await connecting.ConfigureAwait(false); }
            catch (OperationCanceledException) when (deadline.IsCancellationRequested && !linked.IsCancellationRequested)
            { throw new WifiConnectionException(WifiConnectionFailure.Timeout); }
            associated = true;
            sessions.SetConnection(connection, null, sessionId);
            using var addressDeadline = new CancellationTokenSource(options.AddressTimeout, _clock);
            using var addressToken = CancellationTokenSource.CreateLinkedTokenSource(linked.Token, addressDeadline.Token);
            try
            {
                while (true)
                {
                    addressToken.Token.ThrowIfCancellationRequested();
                    var actual = await backend.GetCurrentAsync(request.InterfaceId, addressToken.Token).ConfigureAwait(false);
                    if (actual is null || actual.InterfaceId != request.InterfaceId || actual.Ssid != connection.Ssid)
                        throw new WifiConnectionException(WifiConnectionFailure.NetworkUnavailable);
                    var network = await FindNetworkAsync(actual.InterfaceId, addressToken.Token).ConfigureAwait(false);
                    if (network is not null)
                    {
                        var ready = sessions.SetConnection(actual, network, sessionId);
                        logger.Information("Wi-Fi ready: session {Session}, IPv4 {Ip}, subnet {Subnet}, gateway {Gateway}",
                            ready.SessionId, ready.Ipv4, ready.Subnet, ready.Gateway);
                        return Result(WifiConnectionFailure.None, request);
                    }
                    await Task.Delay(options.AddressPollInterval, _clock, addressToken.Token).ConfigureAwait(false);
                }
            }
            catch (OperationCanceledException) when (addressDeadline.IsCancellationRequested && !linked.IsCancellationRequested)
            { return Result(WifiConnectionFailure.AddressTimeout, request); }
        }
        catch (Exception exception)
        {
            var failure = MapFailure(exception, linked.IsCancellationRequested);
            logger.Information("Wi-Fi connection failed: {Failure}, native/reason {Code}, error type {ErrorType}",
                failure, (exception as WifiConnectionException)?.NativeCode ?? (exception as NativeWifiException)?.NativeCode, exception.GetType().Name);
            if (associated && token.IsCancellationRequested && !_lifetime.IsCancellationRequested)
                try { await backend.DisconnectAsync(request.InterfaceId, options.DisconnectTimeout, CancellationToken.None).ConfigureAwait(false); } catch { }
            if (sessionId != Guid.Empty)
            {
                sessions.SetState(sessionId, WifiConnectionState.Failed);
                if (!_lifetime.IsCancellationRequested)
                    try { await RefreshAsync(CancellationToken.None).ConfigureAwait(false); } catch { }
            }
            return Result(failure, request);
        }
        finally
        {
            request.ClearCredentials();
            if (ownsWlan) coordinator.Gate.Release();
            _operations.Release();
        }
    }

    public Task<WifiConnectionResult> DisconnectAsync(CancellationToken cancellationToken = default)
    {
        lock (_tasks)
        {
            if (!_operations.Wait(0)) return Task.FromResult(Result(WifiConnectionFailure.Busy));
            var task = DisconnectCoreAsync(cancellationToken);
            _pending = task;
            return task;
        }
    }
    private async Task<WifiConnectionResult> DisconnectCoreAsync(CancellationToken token)
    {
        using var linked = CancellationTokenSource.CreateLinkedTokenSource(token, _lifetime.Token);
        var ownsWlan = false;
        try
        {
            var current = sessions.Current;
            if (current.IsInterfaceSelection && current.Network?.IsWireless != true)
                return Result(WifiConnectionFailure.NetworkUnavailable);
            if (current.InterfaceId is not { } id) { sessions.Clear(); return Result(WifiConnectionFailure.None); }
            sessions.SetState(current.SessionId, WifiConnectionState.Disconnecting);
            await StopSessionOperationsAsync().ConfigureAwait(false);
            await coordinator.Gate.WaitAsync(linked.Token).ConfigureAwait(false);
            ownsWlan = true;
            await backend.DisconnectAsync(id, options.DisconnectTimeout, linked.Token).ConfigureAwait(false);
            sessions.Clear();
            logger.Information("Wi-Fi disconnected: interface {Interface}, session {Session}", id, current.SessionId);
            return Result(WifiConnectionFailure.None);
        }
        catch (Exception exception)
        {
            var failure = MapFailure(exception, linked.IsCancellationRequested);
            try { await RefreshAsync(CancellationToken.None).ConfigureAwait(false); } catch { }
            return Result(failure);
        }
        finally { if (ownsWlan) coordinator.Gate.Release(); _operations.Release(); }
    }

    private async Task WatchAsync()
    {
        try
        {
            while (true)
            {
                await Task.Delay(options.SessionRefreshInterval, _clock, _lifetime.Token).ConfigureAwait(false);
                if (!await _operations.WaitAsync(0, _lifetime.Token).ConfigureAwait(false)) continue;
                try { await RefreshAsync(_lifetime.Token).ConfigureAwait(false); }
                catch (OperationCanceledException) when (_lifetime.IsCancellationRequested) { throw; }
                catch (Exception ex) { logger.Debug("Wi-Fi session refresh unavailable: {ErrorType}", ex.GetType().Name); }
                finally { _operations.Release(); }
            }
        }
        catch (OperationCanceledException) when (_lifetime.IsCancellationRequested) { }
    }
    private async Task RefreshAsync(CancellationToken token)
    {
        var previous = sessions.Current;
        if (previous.IsInterfaceSelection && previous.Network is { } selected)
        {
            if (!await networks.IsCurrentAsync(selected, token).ConfigureAwait(false))
            {
                if (sessions.Current.SessionId != previous.SessionId) return;
                await StopSessionOperationsAsync(includeSignal: selected.IsWireless).ConfigureAwait(false);
                sessions.Clear(previous.SessionId);
            }
            else if (selected.IsWireless)
            {
                var associated = await backend.GetCurrentAsync(previous.InterfaceId, token).ConfigureAwait(false);
                if (associated is not null && associated.InterfaceId == previous.InterfaceId)
                    sessions.SetConnection(associated, selected, previous.SessionId);
            }
            return;
        }
        var connection = await backend.GetCurrentAsync(previous.InterfaceId, token).ConfigureAwait(false);
        var network = connection is null ? null : await FindNetworkAsync(connection.InterfaceId, token).ConfigureAwait(false);
        if (sessions.Current.SessionId != previous.SessionId) return;
        var changed = connection is null ? previous.SessionId != Guid.Empty : previous.InterfaceId != connection.InterfaceId ||
            previous.Ssid != connection.Ssid || previous.Network is { } old && (network is null || !old.HasSameContext(network));
        if (changed) await StopSessionOperationsAsync().ConfigureAwait(false);
        if (connection is null) sessions.Clear(previous.SessionId);
        else sessions.SetConnection(connection, network, previous.SessionId);
        if (previous.SessionId != sessions.Current.SessionId)
            logger.Information("Network session changed: {PreviousSession} -> {Session}", previous.SessionId, sessions.Current.SessionId);
    }
    private async Task<LocalNetworkInfo?> FindNetworkAsync(Guid id, CancellationToken token) =>
        (await networks.GetNetworksAsync(token).ConfigureAwait(false)).FirstOrDefault(n => Guid.TryParse(n.InterfaceId, out var found) && found == id);
    private async Task StopSessionOperationsAsync(bool includeSignal = true)
    {
        if (includeSignal && signal is not null) await signal.StopAsync().ConfigureAwait(false);
        if (devices is not null) await devices.ResetAsync().ConfigureAwait(false);
        identityCache?.ResetSession();
    }
    private WifiConnectionResult Result(WifiConnectionFailure failure, WifiConnectionRequest? request = null)
    {
        var current = sessions.Current;
        return new(failure == WifiConnectionFailure.None,
            failure is WifiConnectionFailure.None or WifiConnectionFailure.AddressTimeout ? current.State : WifiConnectionState.Failed,
            failure, Core.Network.WifiConnectionPolicy.Message(failure), request?.Ssid ?? current.Ssid ?? string.Empty,
            failure == WifiConnectionFailure.None ? current.Bssid : request?.Bssid,
            request?.InterfaceId ?? current.InterfaceId ?? Guid.Empty, current.ConnectedAt);
    }
    internal static WifiConnectionFailure MapFailure(Exception exception, bool cancelled) => cancelled
        ? WifiConnectionFailure.Cancelled : exception switch
        {
            WifiConnectionException failure => failure.Failure,
            TimeoutException => WifiConnectionFailure.Timeout,
            WifiException wifi => wifi.Kind switch
            {
                WifiErrorKind.AccessDenied => WifiConnectionFailure.AccessDenied, WifiErrorKind.NoAdapter => WifiConnectionFailure.NoAdapter,
                WifiErrorKind.RadioOff => WifiConnectionFailure.RadioOff, WifiErrorKind.ServiceUnavailable => WifiConnectionFailure.ServiceUnavailable,
                WifiErrorKind.Timeout => WifiConnectionFailure.Timeout, _ => WifiConnectionFailure.Unexpected
            },
            _ => WifiConnectionFailure.Unexpected
        };
    public async Task StopAsync()
    {
        _lifetime.Cancel();
        Task pending; Task initialization;
        lock (_tasks) { pending = _pending; initialization = _initialization ?? Task.CompletedTask; }
        await Task.WhenAll(pending, initialization).ConfigureAwait(false);
        await _watcher.ConfigureAwait(false);
    }
    public void Dispose() => _lifetime.Cancel();
    private sealed class StateProgress(Action<WifiConnectionState> update) : IProgress<WifiConnectionState>
    { public void Report(WifiConnectionState value) => update(value); }
}
