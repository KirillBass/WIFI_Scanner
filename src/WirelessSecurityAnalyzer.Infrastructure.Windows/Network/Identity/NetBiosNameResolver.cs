using System.Buffers.Binary;
using System.Net;
using System.Text;
using Serilog;
using WirelessSecurityAnalyzer.Core.Interfaces;
using WirelessSecurityAnalyzer.Core.Models;
using WirelessSecurityAnalyzer.Core.Network;

namespace WirelessSecurityAnalyzer.Infrastructure.Windows.Network.Identity;

public sealed class NetBiosNameResolver(IIdentityDatagramClient datagrams, DeviceIdentityOptions options, ILogger logger) : IDeviceNameResolver
{
    public DeviceNameSource Source => DeviceNameSource.NetBios;

    public async Task<DeviceIdentity?> ResolveAsync(LocalNetworkInfo network, NetworkDevice device, CancellationToken cancellationToken)
    {
        if (device.IsLocalMachine) return null;
        var id = DnsPacket.NewId(); string? name = null;
        await datagrams.QueryAsync(network, new(device.IpAddress, 137), [BuildQuery(id)], options.QueryTimeout, packet =>
        {
            try { name ??= ParseName(packet.Data, id); }
            catch (FormatException exception) { logger.Debug(exception, "Malformed NetBIOS name response"); }
        }, cancellationToken, isComplete: () => name is not null).ConfigureAwait(false);
        return name is null ? null : new() { Hostname = name, HostnameSource = Source };
    }

    internal static byte[] BuildQuery(ushort id)
    {
        var wildcard = new byte[16]; wildcard[0] = (byte)'*';
        var encoded = string.Concat(wildcard.SelectMany(b => new[] { (char)('A' + (b >> 4)), (char)('A' + (b & 15)) }));
        return DnsPacket.Query(id, [new(encoded, 0x21)]);
    }

    internal static string? ParseName(byte[] data, ushort expectedId)
    {
        var message = DnsPacket.Parse(data, netBios: true);
        if (message.Id != expectedId || !message.IsAnswer) return null;
        foreach (var record in message.Records.Where(r => r.Type == 0x21 && r.Class == 1))
        {
            if (record.Raw.Length < 1 || record.Raw.Length < 1 + record.Raw[0] * 18 + 46)
                throw new FormatException("Truncated NBSTAT names/statistics.");
            for (var i = 0; i < record.Raw[0]; i++)
            {
                var entry = record.Raw.AsSpan(1 + i * 18, 18);
                var flags = BinaryPrimitives.ReadUInt16BigEndian(entry[16..]);
                if (entry[15] != 0 || (flags & 0x8000) != 0) continue;
                var name = DeviceIdentityMerger.Clean(Encoding.ASCII.GetString(entry[..15]).Trim());
                if (name is not null && name != "*") return name;
            }
        }
        return null;
    }
}
