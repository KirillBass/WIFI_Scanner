using WirelessSecurityAnalyzer.Core.Models;

namespace WirelessSecurityAnalyzer.Core.Interfaces;

public interface INetworkSessionService
{
    NetworkSession Current { get; }
    event EventHandler<NetworkSession>? Updated;
    NetworkSession BeginConnection(WifiConnectionRequest request);
    NetworkSession SetConnection(WifiConnectionInfo connection, LocalNetworkInfo? network, Guid? expectedSession = null);
    NetworkSession SelectNetwork(LocalNetworkInfo network);
    void SetState(Guid sessionId, WifiConnectionState state);
    void Clear(Guid? expectedSession = null);
}
