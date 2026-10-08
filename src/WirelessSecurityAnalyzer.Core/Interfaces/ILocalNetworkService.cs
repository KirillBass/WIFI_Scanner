using WirelessSecurityAnalyzer.Core.Models;

namespace WirelessSecurityAnalyzer.Core.Interfaces;

public interface ILocalNetworkService
{
    /// <summary>Suitable active IPv4 contexts, in documented preference order.</summary>
    Task<IReadOnlyList<LocalNetworkInfo>> GetNetworksAsync(CancellationToken cancellationToken = default);
    Task<bool> IsCurrentAsync(LocalNetworkInfo network, CancellationToken cancellationToken = default);
}
