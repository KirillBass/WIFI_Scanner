namespace WirelessSecurityAnalyzer.Core.Models;

/// <summary>Immutable network context. No credentials or WLAN profile are retained.</summary>
public sealed record NetworkSession(Guid SessionId, long Version, WifiConnectionState State,
    string? Ssid, string? Bssid, Guid? InterfaceId, string? InterfaceName,
    LocalNetworkInfo? Network, DateTimeOffset? ConnectedAt, WifiSecurityInfo Security)
{
    public bool IsInterfaceSelection { get; init; }
    public static NetworkSession Empty { get; } = new(Guid.Empty, 0, WifiConnectionState.Disconnected,
        null, null, null, null, null, null, WifiSecurityInfo.Unknown);
    public bool IsConnected => State is WifiConnectionState.Connected or WifiConnectionState.ObtainingAddress
        or WifiConnectionState.Ready or WifiConnectionState.Disconnecting;
    public bool IsReadyForAudit => State == WifiConnectionState.Ready && Network is not null;
    public string? Ipv4 => Network?.LocalIpv4.ToString();
    public int? PrefixLength => Network?.PrefixLength;
    public string? Subnet => Network is { } n ? $"{n.NetworkAddress}/{n.PrefixLength}" : null;
    public string? Gateway => Network?.Gateway?.ToString();
}
