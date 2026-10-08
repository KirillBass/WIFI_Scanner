using System.Net;
using WirelessSecurityAnalyzer.Core.Models;

namespace WirelessSecurityAnalyzer.Core.Interfaces;

public interface INeighborTableReader
{
    Task<IReadOnlyList<NeighborEntry>> ReadAsync(LocalNetworkInfo network, CancellationToken cancellationToken = default);
}

public interface IHostProbe
{
    Task<HostProbeResult> ProbeAsync(LocalNetworkInfo network, IPAddress address, int timeoutMs,
        CancellationToken cancellationToken = default);
}

public interface IHostnameResolver
{
    Task<string?> ResolveAsync(LocalNetworkInfo network, IPAddress address, int timeoutMs,
        CancellationToken cancellationToken = default);
}
