using System.Buffers.Binary;
using System.Net;
using System.Net.Sockets;

namespace WirelessSecurityAnalyzer.Core.Network;

/// <summary>Pure IPv4 arithmetic. No enumeration or network operations until explicitly requested.</summary>
public static class SubnetCalculator
{
    public static uint ToUInt32(IPAddress address)
    {
        ArgumentNullException.ThrowIfNull(address);
        if (address.AddressFamily != AddressFamily.InterNetwork)
            throw new ArgumentException("An IPv4 address is required.", nameof(address));
        return BinaryPrimitives.ReadUInt32BigEndian(address.GetAddressBytes());
    }

    public static IPAddress ToAddress(uint value)
    {
        Span<byte> bytes = stackalloc byte[4];
        BinaryPrimitives.WriteUInt32BigEndian(bytes, value);
        return new IPAddress(bytes);
    }

    public static Ipv4Subnet Calculate(IPAddress address, int prefixLength)
    {
        if (prefixLength is < 0 or > 32) throw new ArgumentOutOfRangeException(nameof(prefixLength));
        var ip = ToUInt32(address);
        var mask = prefixLength == 0 ? 0u : uint.MaxValue << (32 - prefixLength);
        var network = ip & mask;
        var last = network | ~mask;
        // /31 uses both endpoints (RFC 3021); /32 is a single host. The MVP sweep rejects both explicitly.
        var count = prefixLength >= 31 ? 1UL << (32 - prefixLength) : (1UL << (32 - prefixLength)) - 2;
        return new Ipv4Subnet(prefixLength, ToAddress(mask), ToAddress(network),
            prefixLength >= 31 ? null : ToAddress(last),
            ToAddress(prefixLength >= 31 ? network : network + 1),
            ToAddress(prefixLength >= 31 ? last : last - 1), count);
    }

    public static bool IsUsableUnicast(IPAddress address)
    {
        if (address.AddressFamily != AddressFamily.InterNetwork) return false;
        var bytes = address.GetAddressBytes();
        return bytes[0] is > 0 and < 224 && bytes[0] != 127 && !(bytes[0] == 169 && bytes[1] == 254);
    }
}

public sealed record Ipv4Subnet(int PrefixLength, IPAddress Mask, IPAddress NetworkAddress,
    IPAddress? BroadcastAddress, IPAddress FirstHost, IPAddress LastHost, ulong HostCount)
{
    public bool ContainsHost(IPAddress address)
    {
        if (!SubnetCalculator.IsUsableUnicast(address)) return false;
        var value = SubnetCalculator.ToUInt32(address);
        return value >= SubnetCalculator.ToUInt32(FirstHost) && value <= SubnetCalculator.ToUInt32(LastHost);
    }

    public void EnsureSweepAllowed(int maximumHosts = 1024)
    {
        if (maximumHosts is < 1 or > 1024) throw new ArgumentOutOfRangeException(nameof(maximumHosts));
        if (PrefixLength >= 31)
            throw new NetworkDiscoveryException(NetworkDiscoveryError.UnsupportedSubnet, "Automatic discovery does not support /31 or /32.");
        if (HostCount > (ulong)maximumHosts)
            throw new NetworkDiscoveryException(NetworkDiscoveryError.SubnetTooLarge, $"Subnet has {HostCount} candidate hosts; maximum is {maximumHosts}.");
    }

    public IEnumerable<IPAddress> EnumerateHosts(int maximumHosts = 1024)
    {
        EnsureSweepAllowed(maximumHosts);
        return Enumerate();
    }

    private IEnumerable<IPAddress> Enumerate()
    {
        var first = SubnetCalculator.ToUInt32(FirstHost);
        for (ulong offset = 0; offset < HostCount; offset++)
            yield return SubnetCalculator.ToAddress(checked(first + (uint)offset));
    }
}
