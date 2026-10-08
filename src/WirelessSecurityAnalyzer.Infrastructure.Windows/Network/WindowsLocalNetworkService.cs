using System.Net.NetworkInformation;
using System.Net.Sockets;
using Serilog;
using WirelessSecurityAnalyzer.Core.Interfaces;
using WirelessSecurityAnalyzer.Core.Models;
using WirelessSecurityAnalyzer.Core.Network;

namespace WirelessSecurityAnalyzer.Infrastructure.Windows.Network;

public sealed class WindowsLocalNetworkService(ILogger logger) : ILocalNetworkService
{
    public Task<IReadOnlyList<LocalNetworkInfo>> GetNetworksAsync(CancellationToken cancellationToken = default) =>
        Task.Run<IReadOnlyList<LocalNetworkInfo>>(() =>
        {
            EnsureWindows();
            cancellationToken.ThrowIfCancellationRequested();
            var networks = new List<LocalNetworkInfo>();
            foreach (var adapter in NetworkInterface.GetAllNetworkInterfaces())
            {
                cancellationToken.ThrowIfCancellationRequested();
                if (adapter.OperationalStatus != OperationalStatus.Up ||
                    adapter.NetworkInterfaceType is not (NetworkInterfaceType.Wireless80211 or NetworkInterfaceType.Ethernet or NetworkInterfaceType.GigabitEthernet or NetworkInterfaceType.FastEthernetFx or NetworkInterfaceType.FastEthernetT)) continue;
                try
                {
                    var properties = adapter.GetIPProperties();
                    var index = properties.GetIPv4Properties()?.Index;
                    if (index is null or <= 0) continue;
                    var gateways = properties.GatewayAddresses.Select(g => g.Address)
                        .Where(SubnetCalculator.IsUsableUnicast).OrderBy(SubnetCalculator.ToUInt32).ToArray();
                    foreach (var unicast in properties.UnicastAddresses.Where(a =>
                        a.Address.AddressFamily == AddressFamily.InterNetwork && SubnetCalculator.IsUsableUnicast(a.Address) &&
                        a.DuplicateAddressDetectionState is DuplicateAddressDetectionState.Preferred or DuplicateAddressDetectionState.Deprecated))
                    {
                        var subnet = SubnetCalculator.Calculate(unicast.Address, unicast.PrefixLength);
                        if (!subnet.ContainsHost(unicast.Address)) continue;
                        var gateway = gateways.FirstOrDefault(subnet.ContainsHost) ?? gateways.FirstOrDefault();
                        var mac = adapter.GetPhysicalAddress();
                        networks.Add(new LocalNetworkInfo(adapter.Id, index.Value, adapter.Name, adapter.Description,
                            adapter.NetworkInterfaceType, unicast.Address, unicast.PrefixLength, gateway,
                            DeviceStateTracker.ValidMac(mac) ? mac : null));
                    }
                }
                catch (NetworkInformationException exception) { logger.Warning(exception, "Unable to read IPv4 context for {InterfaceId}", adapter.Id); }
            }
            return OrderCandidates(networks);
        }, cancellationToken);

    public async Task<bool> IsCurrentAsync(LocalNetworkInfo network, CancellationToken cancellationToken = default) =>
        (await GetNetworksAsync(cancellationToken).ConfigureAwait(false)).Any(n => n.HasSameContext(network));

    public static IReadOnlyList<LocalNetworkInfo> OrderCandidates(IEnumerable<LocalNetworkInfo> networks) =>
        Array.AsReadOnly(networks.OrderByDescending(n => n.Gateway is not null)
            .ThenByDescending(n => n.IsWireless).ThenBy(n => n.Name, StringComparer.OrdinalIgnoreCase)
            .ThenBy(n => n.InterfaceId, StringComparer.OrdinalIgnoreCase)
            .ThenBy(n => SubnetCalculator.ToUInt32(n.LocalIpv4)).ToArray());

    internal static void EnsureWindows()
    {
        if (!OperatingSystem.IsWindows())
            throw new NetworkDiscoveryException(NetworkDiscoveryError.UnsupportedPlatform, "Local network discovery requires Windows.");
    }
}
