using WirelessSecurityAnalyzer.Core.Models;

namespace WirelessSecurityAnalyzer.Core.Interfaces;

public sealed record DeviceIdentityUpdate(NetworkDevice Device, DeviceIdentity Identity, bool IsComplete = false);

public interface IDeviceIdentityResolver
{
    Task EnrichAsync(LocalNetworkInfo network, IReadOnlyList<NetworkDevice> devices,
        Action<DeviceIdentityUpdate> publish, CancellationToken cancellationToken = default);
}

public interface IDeviceNameResolver
{
    DeviceNameSource Source { get; }
    Task<DeviceIdentity?> ResolveAsync(LocalNetworkInfo network, NetworkDevice device, CancellationToken cancellationToken);
}

public interface INetworkIdentityResolver
{
    DeviceNameSource Source { get; }
    Task ResolveAsync(LocalNetworkInfo network, IReadOnlyList<NetworkDevice> devices,
        Action<DeviceIdentityUpdate> publish, CancellationToken cancellationToken);
}
