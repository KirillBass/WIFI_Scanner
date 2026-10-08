using System.Net;
using System.Net.NetworkInformation;
using WirelessSecurityAnalyzer.Core.Network;

namespace WirelessSecurityAnalyzer.Core.Models;

public sealed record LocalNetworkInfo(string InterfaceId, int InterfaceIndex, string Name,
    string InterfaceDescription, NetworkInterfaceType InterfaceType, IPAddress LocalIpv4,
    int PrefixLength, IPAddress? Gateway, PhysicalAddress? LocalMacAddress)
{
    public bool IsWireless => InterfaceType == NetworkInterfaceType.Wireless80211;
    public Ipv4Subnet Subnet => SubnetCalculator.Calculate(LocalIpv4, PrefixLength);
    public IPAddress SubnetMask => Subnet.Mask;
    public IPAddress NetworkAddress => Subnet.NetworkAddress;
    public IPAddress? BroadcastAddress => Subnet.BroadcastAddress;
    public string DisplayName => $"{Name} · {LocalIpv4}/{PrefixLength}";
    public bool HasSameContext(LocalNetworkInfo other) =>
        string.Equals(InterfaceId, other.InterfaceId, StringComparison.OrdinalIgnoreCase) &&
        InterfaceIndex == other.InterfaceIndex && LocalIpv4.Equals(other.LocalIpv4) &&
        PrefixLength == other.PrefixLength && Equals(Gateway, other.Gateway);
}
