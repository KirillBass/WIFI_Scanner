using System.Net;
using System.Net.NetworkInformation;
using System.Net.Sockets;
using Serilog;
using WirelessSecurityAnalyzer.Core.Interfaces;
using WirelessSecurityAnalyzer.Core.Models;
using WirelessSecurityAnalyzer.Core.Network;
using WirelessSecurityAnalyzer.Infrastructure.Windows.Network.Identity;

namespace WirelessSecurityAnalyzer.Infrastructure.Windows.Network;

/// <summary>PTR queries to DNS servers on the selected subnet. Avoids the OS-wide resolver,
/// which may send identifiers to a public DNS server or a VPN.</summary>
public sealed class HostnameResolver(ILogger logger, IIdentityDatagramClient datagrams, ILocalDnsServerProvider? dnsServers = null) : IHostnameResolver
{
    public async Task<string?> ResolveAsync(LocalNetworkInfo network, IPAddress address, int timeoutMs,
        CancellationToken cancellationToken = default)
    {
        if (!network.Subnet.ContainsHost(address)) return null;
        var servers = (dnsServers ?? new LocalDnsServerProvider()).GetServers(network)
            .Where(ip => network.Subnet.ContainsHost(ip)).Distinct().Take(3).ToArray();
        var id = DnsPacket.NewId();
        var question = DnsPacket.Reverse(address);
        string? result = null;
        using var timeout = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
        timeout.CancelAfter(Math.Clamp(timeoutMs, 1, 2000));
        try
        {
            foreach (var server in servers)
            {
                try
                {
                    await datagrams.QueryAsync(network, new IPEndPoint(server, 53),
                        [DnsPacket.Query(id, [new(question, 12)])], TimeSpan.FromMilliseconds(Math.Clamp(timeoutMs, 1, 2000) / (double)servers.Length), packet =>
                        {
                            try
                            {
                                var message = DnsPacket.Parse(packet.Data);
                                if (message.Id != id || !message.IsAnswer || !message.Questions.Any(q => q.Type == 12 && q.Name.Equals(question, StringComparison.OrdinalIgnoreCase))) return;
                                result ??= message.Records.Where(r => r.Type == 12 && r.Class == 1 && r.Name.Equals(question, StringComparison.OrdinalIgnoreCase))
                                    .Select(r => DeviceIdentityMerger.Clean(r.Target)).FirstOrDefault(n => n is not null && !IPAddress.TryParse(n, out _));
                            }
                            catch (FormatException exception) { logger.Debug(exception, "Malformed local reverse DNS response"); }
                        }, timeout.Token, isComplete: () => result is not null).ConfigureAwait(false);
                }
                catch (SocketException exception) { logger.Debug(exception, "Local DNS server {Server} unavailable", server); }
                if (result is not null) break;
            }
        }
        catch (OperationCanceledException) when (!cancellationToken.IsCancellationRequested) { }
        cancellationToken.ThrowIfCancellationRequested();
        return result;
    }
}

public interface ILocalDnsServerProvider
{
    IReadOnlyList<IPAddress> GetServers(LocalNetworkInfo network);
}

public sealed class LocalDnsServerProvider : ILocalDnsServerProvider
{
    public IReadOnlyList<IPAddress> GetServers(LocalNetworkInfo network)
    {
        var adapter = NetworkInterface.GetAllNetworkInterfaces().FirstOrDefault(n => n.OperationalStatus == OperationalStatus.Up &&
            n.Id.Equals(network.InterfaceId, StringComparison.OrdinalIgnoreCase));
        if (adapter is null) return [];
        var properties = adapter.GetIPProperties();
        if (WindowsLocalNetworkService.GetIpv4Index(adapter, properties) != network.InterfaceIndex ||
            !properties.UnicastAddresses.Any(a => a.Address.Equals(network.LocalIpv4))) return [];
        return SelectServers(network, properties.DnsAddresses);
    }

    internal static IReadOnlyList<IPAddress> SelectServers(LocalNetworkInfo network, IEnumerable<IPAddress> configured) =>
        configured.Where(network.Subnet.ContainsHost)
            .Concat(network.Gateway is { } gateway && network.Subnet.ContainsHost(gateway) ? [gateway] : [])
            .Distinct().Take(3).ToArray();
}
