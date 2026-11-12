using System.Net;
using System.Net.NetworkInformation;
using WirelessSecurityAnalyzer.Core.Models;
using WirelessSecurityAnalyzer.Core.NetworkAudit;

namespace WirelessSecurityAnalyzer.Infrastructure.Windows.NetworkAudit;

/// <summary>Reads the local listener table; does not infer or probe ports on other devices.</summary>
public sealed class LocalTcpPortProvider : ILocalTcpPortProvider
{
    public IReadOnlyList<int> GetListeningPorts(LocalNetworkInfo network) => SelectPorts(network,
        IPGlobalProperties.GetIPGlobalProperties().GetActiveTcpListeners());
    internal static IReadOnlyList<int> SelectPorts(LocalNetworkInfo network, IEnumerable<IPEndPoint> endpoints) =>
        Array.AsReadOnly(endpoints.Where(e => e.Address.Equals(network.LocalIpv4) || e.Address.Equals(IPAddress.Any) ||
            e.Address.Equals(IPAddress.IPv6Any)).Select(e => e.Port).Where(p => p is >= 1 and <= 65535).Distinct().Order().ToArray());
}
