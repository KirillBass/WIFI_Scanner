using System.Buffers.Binary;
using System.Net;
using System.Net.Sockets;
using WirelessSecurityAnalyzer.Core.Interfaces;
using WirelessSecurityAnalyzer.Core.Models;
using WirelessSecurityAnalyzer.Core.Network;

namespace WirelessSecurityAnalyzer.Infrastructure.Windows.Network.Identity;

/// <summary>RFC 4795 2.4: a reverse PTR query uses unicast TCP, never unicast UDP.</summary>
public sealed class LlmnrNameResolver(DeviceIdentityOptions options) : IDeviceNameResolver
{
    public DeviceNameSource Source => DeviceNameSource.Llmnr;
    public async Task<DeviceIdentity?> ResolveAsync(LocalNetworkInfo network, NetworkDevice device, CancellationToken cancellationToken)
    {
        if (device.IsLocalMachine || !network.Subnet.ContainsHost(device.IpAddress)) return null;
        using var deadline = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
        deadline.CancelAfter(options.QueryTimeout);
        using var client = new TcpClient(AddressFamily.InterNetwork);
        client.Client.Bind(new IPEndPoint(network.LocalIpv4, 0));
        IdentitySocketScope.SelectInterface(client.Client, network);
        await client.ConnectAsync(device.IpAddress, 5355, deadline.Token).ConfigureAwait(false);
        var id = DnsPacket.NewId(); var question = DnsPacket.Reverse(device.IpAddress);
        var query = DnsPacket.Query(id, [new(question, 12)]);
        var length = new byte[2]; BinaryPrimitives.WriteUInt16BigEndian(length, checked((ushort)query.Length));
        var stream = client.GetStream();
        await stream.WriteAsync(length, deadline.Token).ConfigureAwait(false);
        await stream.WriteAsync(query, deadline.Token).ConfigureAwait(false);
        await stream.ReadExactlyAsync(length, deadline.Token).ConfigureAwait(false);
        var count = BinaryPrimitives.ReadUInt16BigEndian(length);
        if (count is < 12 or > 8192) throw new FormatException("Invalid LLMNR response length.");
        var response = new byte[count]; await stream.ReadExactlyAsync(response, deadline.Token).ConfigureAwait(false);
        var name = ParseName(response, id, question);
        return name is null ? null : new() { Hostname = name, HostnameSource = Source };
    }

    internal static string? ParseName(byte[] response, ushort id, string question)
    {
        var message = DnsPacket.Parse(response);
        if (message.Id != id || !message.IsAnswer || (message.Flags & 0x0400) != 0 || message.Questions.Count != 1 ||
            !message.Questions[0].Name.Equals(question, StringComparison.OrdinalIgnoreCase) || message.Questions[0].Type != 12) return null;
        return message.Records.Where(r => r.Type == 12 && r.Class == 1 && r.Name.Equals(question, StringComparison.OrdinalIgnoreCase))
            .Select(r => DeviceIdentityMerger.Clean(r.Target)).FirstOrDefault(n => n is not null && !IPAddress.TryParse(n, out _));
    }
}
