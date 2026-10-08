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
            .Where(ip => network.Subnet.ContainsHost(ip)).Distinct().Take(2).ToArray();
        var id = DnsPacket.NewId();
        var question = DnsPacket.Reverse(address);
        string? result = null;
        using var timeout = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
        timeout.CancelAfter(Math.Clamp(timeoutMs, 1, 2000));
        try
        {
            foreach (var server in servers)
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
                if (result is not null) break;
            }
        }
        catch (OperationCanceledException) when (!cancellationToken.IsCancellationRequested) { }
        catch (SocketException exception) { logger.Debug(exception, "Local reverse DNS unavailable"); }
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
    public IReadOnlyList<IPAddress> GetServers(LocalNetworkInfo network) =>
        NetworkInterface.GetAllNetworkInterfaces().FirstOrDefault(n => n.Id.Equals(network.InterfaceId, StringComparison.OrdinalIgnoreCase))
            ?.GetIPProperties().DnsAddresses.ToArray() ?? [];
}
