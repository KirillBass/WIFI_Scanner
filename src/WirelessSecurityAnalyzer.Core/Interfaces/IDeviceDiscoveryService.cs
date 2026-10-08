using WirelessSecurityAnalyzer.Core.Models;
using WirelessSecurityAnalyzer.Core.Network;

namespace WirelessSecurityAnalyzer.Core.Interfaces;

public interface IDeviceDiscoveryService
{
    Task<DeviceDiscoveryResult> DiscoverAsync(LocalNetworkInfo network, DeviceDiscoveryOptions options,
        CancellationToken cancellationToken = default, IProgress<DeviceDiscoveryProgress>? progress = null);
}
