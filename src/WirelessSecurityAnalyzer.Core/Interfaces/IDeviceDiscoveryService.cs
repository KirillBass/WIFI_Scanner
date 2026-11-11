using WirelessSecurityAnalyzer.Core.Models;
using WirelessSecurityAnalyzer.Core.Network;

namespace WirelessSecurityAnalyzer.Core.Interfaces;

public interface IDeviceDiscoveryService
{
    Task<DeviceDiscoveryResult> DiscoverAsync(LocalNetworkInfo network, DeviceDiscoveryOptions options,
        CancellationToken cancellationToken = default, IProgress<DeviceDiscoveryProgress>? progress = null);
}

/// <summary>Callbacks are serialized by the implementation and never depend on a UI dispatcher.</summary>
public interface IStreamingDeviceDiscoveryService : IDeviceDiscoveryService
{
    Task<DeviceDiscoveryResult> DiscoverStreamingAsync(LocalNetworkInfo network, DeviceDiscoveryOptions options,
        DeviceDiscoveryContext context, Action<DeviceDiscoveryEvent> publish, CancellationToken cancellationToken = default);
}
