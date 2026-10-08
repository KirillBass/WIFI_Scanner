using System.Net;
using System.Net.NetworkInformation;
using Serilog;
using WirelessSecurityAnalyzer.Core.Interfaces;
using WirelessSecurityAnalyzer.Core.Models;
using WirelessSecurityAnalyzer.Infrastructure.Windows.Interop;

namespace WirelessSecurityAnalyzer.Infrastructure.Windows.Network;

public sealed class PingHostProbe(ILogger logger) : IHostProbe
{
    public async Task<HostProbeResult> ProbeAsync(LocalNetworkInfo network, IPAddress address, int timeoutMs,
        CancellationToken cancellationToken = default)
    {
        WindowsLocalNetworkService.EnsureWindows();
        cancellationToken.ThrowIfCancellationRequested();
        if (!network.Subnet.ContainsHost(address) || address.Equals(network.LocalIpv4)) return new(false, null, false);
        var destination = new SockaddrInet { Family = IpHelperNativeMethods.AfInet,
            Ipv4Address = BitConverter.ToUInt32(address.GetAddressBytes()) };
        // Ping uses OS routing: refuse probes routed through another adapter (e.g. a VPN).
        var code = IpHelperNativeMethods.GetBestInterfaceEx(ref destination, out var routeIndex);
        if (code != 0 || routeIndex != network.InterfaceIndex) return new(false, null, false);
        try
        {
            using var ping = new Ping();
            var reply = await ping.SendPingAsync(address, TimeSpan.FromMilliseconds(timeoutMs),
                new byte[16], new PingOptions(), cancellationToken).ConfigureAwait(false);
            return reply.Status == IPStatus.Success && reply.Address.Equals(address)
                ? new(true, TimeSpan.FromMilliseconds(reply.RoundtripTime)) : new(false, null);
        }
        catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested) { throw; }
        catch (Exception exception) when (exception is PingException or System.Net.Sockets.SocketException or InvalidOperationException)
        {
            logger.Debug(exception, "ICMP probe failed for {Address}", address);
            return new(false, null, HadError: true);
        }
    }
}
