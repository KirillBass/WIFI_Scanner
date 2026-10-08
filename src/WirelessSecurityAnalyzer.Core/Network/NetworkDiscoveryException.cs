namespace WirelessSecurityAnalyzer.Core.Network;

public enum NetworkDiscoveryError
{
    UnsupportedPlatform, NoInterface, ContextChanged, SubnetTooLarge, UnsupportedSubnet,
    NeighborTableFailed, ProbeFailed, Busy, Unexpected
}

public sealed class NetworkDiscoveryException(NetworkDiscoveryError kind, string message, Exception? inner = null)
    : Exception(message, inner)
{
    public NetworkDiscoveryError Kind { get; } = kind;
}
