using System.Net.NetworkInformation;

namespace WirelessSecurityAnalyzer.Core.Network;

public static class MacAddressHelper
{
    public static bool IsLocallyAdministered(PhysicalAddress? address) =>
        address?.GetAddressBytes() is { Length: 6 } bytes && (bytes[0] & 0x02) != 0;
}
