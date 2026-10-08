using System.Net;
using System.Net.Sockets;
using WirelessSecurityAnalyzer.Core.Models;

namespace WirelessSecurityAnalyzer.Infrastructure.Windows.Network.Identity;

public sealed record IdentityDatagram(IPEndPoint Sender, byte[] Data);

public interface IIdentityDatagramClient
{
    Task QueryAsync(LocalNetworkInfo network, IPEndPoint destination, IReadOnlyList<byte[]> queries,
        TimeSpan timeout, Action<IdentityDatagram> receive, CancellationToken cancellationToken, Func<bool>? isComplete = null);
}

/// <summary>Only query sockets bound to the chosen IPv4 interface; no capture or responder.</summary>
public sealed class IdentityDatagramClient : IIdentityDatagramClient
{
    public async Task QueryAsync(LocalNetworkInfo network, IPEndPoint destination, IReadOnlyList<byte[]> queries,
        TimeSpan timeout, Action<IdentityDatagram> receive, CancellationToken cancellationToken, Func<bool>? isComplete = null)
    {
        if (!network.Subnet.ContainsHost(destination.Address) &&
            !(destination.Port == 5353 && destination.Address.Equals(IPAddress.Parse("224.0.0.251"))) &&
            !(destination.Port == 1900 && destination.Address.Equals(IPAddress.Parse("239.255.255.250"))))
            throw new ArgumentException("Identity queries must stay on the selected link.", nameof(destination));
        using var udp = new UdpClient(new IPEndPoint(network.LocalIpv4, 0));
        IdentitySocketScope.SelectInterface(udp.Client, network);
        var multicast = destination.Address.GetAddressBytes()[0] is >= 224 and <= 239;
        if (multicast)
        {
            udp.Client.SetSocketOption(SocketOptionLevel.IP, SocketOptionName.MulticastInterface, network.LocalIpv4.GetAddressBytes());
            udp.Client.SetSocketOption(SocketOptionLevel.IP, SocketOptionName.MulticastTimeToLive, destination.Port == 5353 ? 255 : 1);
        }
        using var deadline = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
        deadline.CancelAfter(timeout);
        try
        {
            foreach (var query in queries) await udp.SendAsync(query, destination, deadline.Token).ConfigureAwait(false);
            var count = 0;
            while (count++ < 2048)
            {
                var packet = await udp.ReceiveAsync(deadline.Token).ConfigureAwait(false);
                if ((destination.Port != 1900 && packet.RemoteEndPoint.Port != destination.Port) ||
                    (!multicast && !packet.RemoteEndPoint.Address.Equals(destination.Address)) ||
                    (multicast && !network.Subnet.ContainsHost(packet.RemoteEndPoint.Address))) continue;
                receive(new IdentityDatagram(packet.RemoteEndPoint, packet.Buffer));
                if (isComplete?.Invoke() == true) break;
            }
        }
        catch (OperationCanceledException) when (!cancellationToken.IsCancellationRequested) { }
        cancellationToken.ThrowIfCancellationRequested();
    }
}

internal static class IdentitySocketScope
{
    // Winsock IP_UNICAST_IF = 31 (ws2ipdef.h); no named member in SocketOptionName.
    private const SocketOptionName UnicastInterface = (SocketOptionName)31;
    public static void SelectInterface(Socket socket, LocalNetworkInfo network)
    {
        socket.SetSocketOption(SocketOptionLevel.IP, SocketOptionName.IpTimeToLive, 1);
        if (OperatingSystem.IsWindows())
            socket.SetSocketOption(SocketOptionLevel.IP, UnicastInterface, IPAddress.HostToNetworkOrder(network.InterfaceIndex));
    }
}
