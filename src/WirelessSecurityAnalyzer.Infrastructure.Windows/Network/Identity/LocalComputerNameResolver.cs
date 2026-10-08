using WirelessSecurityAnalyzer.Core.Interfaces;
using WirelessSecurityAnalyzer.Core.Models;

namespace WirelessSecurityAnalyzer.Infrastructure.Windows.Network.Identity;

public sealed class LocalComputerNameResolver : IDeviceNameResolver
{
    public DeviceNameSource Source => DeviceNameSource.LocalComputer;
    public Task<DeviceIdentity?> ResolveAsync(LocalNetworkInfo network, NetworkDevice device, CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        return Task.FromResult<DeviceIdentity?>(device.IsLocalMachine ? new()
        { Hostname = Environment.MachineName, HostnameSource = Source } : null);
    }
}
