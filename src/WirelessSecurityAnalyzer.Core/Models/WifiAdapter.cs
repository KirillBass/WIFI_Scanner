namespace WirelessSecurityAnalyzer.Core.Models;

public enum WifiAdapterState
{
    NotReady, Connected, AdHocNetworkFormed, Disconnecting,
    Disconnected, Associating, Discovering, Authenticating
}

public sealed record WifiAdapter(Guid Id, string Description, WifiAdapterState State);
