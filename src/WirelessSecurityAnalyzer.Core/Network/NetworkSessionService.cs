using WirelessSecurityAnalyzer.Core.Interfaces;
using WirelessSecurityAnalyzer.Core.Models;

namespace WirelessSecurityAnalyzer.Core.Network;

public sealed class NetworkSessionService(TimeProvider? timeProvider = null) : INetworkSessionService
{
    private readonly object _gate = new();
    private readonly TimeProvider _clock = timeProvider ?? TimeProvider.System;
    private NetworkSession _current = NetworkSession.Empty;
    public NetworkSession Current { get { lock (_gate) return _current; } }
    public event EventHandler<NetworkSession>? Updated;

    public NetworkSession BeginConnection(WifiConnectionRequest request) => Change(old => new(Guid.NewGuid(), old.Version,
        WifiConnectionState.Connecting, request.Ssid, null, request.InterfaceId, null, null, null, request.SecurityInfo));

    public NetworkSession SetConnection(WifiConnectionInfo connection, LocalNetworkInfo? network, Guid? expectedSession = null) => Change(old =>
    {
        if (expectedSession is { } expected && expected != old.SessionId) return old;
        var same = old.InterfaceId == connection.InterfaceId && old.SessionId != Guid.Empty &&
            (old.Ssid == connection.Ssid || old.IsInterfaceSelection && network is not null && old.Network?.HasSameContext(network) == true);
        if (old.Network is not null && network is null) same = false;
        if (old.Network is { } previous && network is not null && !previous.HasSameContext(network)) same = false;
        var security = old.Security.Protocol == connection.Security.Protocol && old.Security.Authentication == connection.Security.Authentication &&
            old.Security.GroupCipher == connection.Security.GroupCipher && old.Security.Source == connection.Security.Source &&
            old.Security.PairwiseCiphers.SequenceEqual(connection.Security.PairwiseCiphers) ? old.Security : connection.Security;
        return new(same ? old.SessionId : Guid.NewGuid(), old.Version,
            network is null ? WifiConnectionState.ObtainingAddress : WifiConnectionState.Ready,
            connection.Ssid, connection.Bssid, connection.InterfaceId, connection.InterfaceName, network,
            same ? old.ConnectedAt ?? _clock.GetUtcNow() : _clock.GetUtcNow(), security);
    });

    public void SetState(Guid sessionId, WifiConnectionState state) => Change(old => old.SessionId == sessionId
        ? old with { State = state, Network = state == WifiConnectionState.Failed ? null : old.Network } : old);
    public NetworkSession SelectNetwork(LocalNetworkInfo network) => Change(old =>
        old.IsReadyForAudit && old.Network?.HasSameContext(network) == true ? old :
            new NetworkSession(Guid.NewGuid(), old.Version, WifiConnectionState.Ready, null, null,
                Guid.TryParse(network.InterfaceId, out var id) ? id : null, network.Name, network,
                _clock.GetUtcNow(), WifiSecurityInfo.Unknown) { IsInterfaceSelection = true });

    public void Clear(Guid? expectedSession = null) => Change(old =>
        expectedSession is { } expected && old.SessionId != expected ? old : NetworkSession.Empty with { Version = old.Version });

    private NetworkSession Change(Func<NetworkSession, NetworkSession> update)
    {
        NetworkSession snapshot;
        lock (_gate)
        {
            snapshot = update(_current);
            if (snapshot == _current) return _current;
            _current = snapshot = snapshot with { Version = _current.Version + 1 };
        }
        if (Updated is { } handlers)
            foreach (EventHandler<NetworkSession> handler in handlers.GetInvocationList())
                try { handler(this, snapshot); } catch { /* An observer cannot invalidate committed session state. */ }
        return snapshot;
    }
}
