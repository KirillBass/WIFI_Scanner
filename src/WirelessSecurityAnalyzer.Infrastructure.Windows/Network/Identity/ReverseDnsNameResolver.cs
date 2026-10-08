using WirelessSecurityAnalyzer.Core.Interfaces;
using WirelessSecurityAnalyzer.Core.Models;

namespace WirelessSecurityAnalyzer.Infrastructure.Windows.Network.Identity;

public sealed class ReverseDnsNameResolver(IHostnameResolver hostnames, DeviceIdentityOptions options) : IDeviceNameResolver
{
    public DeviceNameSource Source => DeviceNameSource.ReverseDns;
    public async Task<DeviceIdentity?> ResolveAsync(LocalNetworkInfo network, NetworkDevice device, CancellationToken cancellationToken)
    {
        if (device.IsLocalMachine) return null;
        var name = await hostnames.ResolveAsync(network, device.IpAddress, (int)options.QueryTimeout.TotalMilliseconds, cancellationToken).ConfigureAwait(false);
        return name is null ? null : new() { Hostname = name, HostnameSource = Source };
    }
}
