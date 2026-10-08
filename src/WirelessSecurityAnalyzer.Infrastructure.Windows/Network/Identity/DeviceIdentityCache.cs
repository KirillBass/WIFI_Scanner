using WirelessSecurityAnalyzer.Core.Models;
using WirelessSecurityAnalyzer.Core.Network;

namespace WirelessSecurityAnalyzer.Infrastructure.Windows.Network.Identity;

/// <summary>Process-local, bounded cache, scoped to the selected interface and IPv4 network.</summary>
public sealed class DeviceIdentityCache(DeviceIdentityOptions options, TimeProvider? timeProvider = null)
{
    private readonly TimeProvider _clock = timeProvider ?? TimeProvider.System;
    private readonly object _gate = new();
    private readonly Dictionary<string, Entry> _entries = [];

    public bool TryGet(LocalNetworkInfo network, NetworkDevice device, out DeviceIdentity identity)
    {
        lock (_gate)
        {
            if (_entries.TryGetValue(Key(network, device), out var entry) && _clock.GetUtcNow() < entry.Expires)
            { identity = entry.Identity; return true; }
        }
        identity = new DeviceIdentity();
        return false;
    }

    public void Store(LocalNetworkInfo network, NetworkDevice device, DeviceIdentity identity)
    {
        lock (_gate)
        {
            if (_entries.Count >= 4096)
                foreach (var expiredKey in _entries.OrderBy(p => p.Value.Expires).Take(512).Select(p => p.Key).ToArray()) _entries.Remove(expiredKey);
            var key = Key(network, device);
            var previous = _entries.GetValueOrDefault(key)?.Identity;
            _entries[key] = new Entry(DeviceIdentityMerger.Merge(previous, identity), _clock.GetUtcNow() + options.CacheTtl);
        }
    }

    private static string Key(LocalNetworkInfo network, NetworkDevice device) =>
        $"{network.InterfaceId.ToUpperInvariant()}|{network.InterfaceIndex}|{network.NetworkAddress}/{network.PrefixLength}|{network.Gateway}|" +
        (DeviceStateTracker.ValidMac(device.MacAddress) ? $"MAC:{device.MacAddress}" : $"IP:{device.IpAddress}");
    private sealed record Entry(DeviceIdentity Identity, DateTimeOffset Expires);
}
