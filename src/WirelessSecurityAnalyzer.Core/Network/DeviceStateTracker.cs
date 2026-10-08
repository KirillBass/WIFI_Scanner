using System.Net.NetworkInformation;
using WirelessSecurityAnalyzer.Core.Models;

namespace WirelessSecurityAnalyzer.Core.Network;

/// <summary>Session history for one network context. Called serially by the monitor service.</summary>
public sealed class DeviceStateTracker
{
    private readonly List<TrackedDevice> _devices = [];
    private LocalNetworkInfo? _network;

    public void SetContext(LocalNetworkInfo network)
    {
        if (_network is null || !_network.HasSameContext(network)) _devices.Clear();
        _network = network;
    }

    public IReadOnlyList<NetworkDevice> Apply(DeviceDiscoveryResult result, int offlineAfterMissedScans = 3)
    {
        if (offlineAfterMissedScans < 1) throw new ArgumentOutOfRangeException(nameof(offlineAfterMissedScans));
        SetContext(result.Network);
        var seen = new HashSet<TrackedDevice>();
        foreach (var observation in result.Observations.Where(o => o.IsConfirmed && result.Network.Subnet.ContainsHost(o.IpAddress)))
        {
            var mac = ValidMac(observation.MacAddress) ? observation.MacAddress : null;
            // MAC first; fall back to IP only when a known different MAC does not contradict identity.
            var tracked = mac is null ? null : _devices.FirstOrDefault(d => Equals(d.Device.MacAddress, mac) && !seen.Contains(d));
            tracked ??= _devices.FirstOrDefault(d => !seen.Contains(d) && d.Device.IpAddress.Equals(observation.IpAddress) &&
                (mac is null || d.Device.MacAddress is null || Equals(d.Device.MacAddress, mac)));
            var firstSeen = tracked?.Device.FirstSeen ?? observation.ObservedAt;
            var lastSeen = tracked is null || observation.ObservedAt > tracked.Device.LastSeen ? observation.ObservedAt : tracked.Device.LastSeen;
            var identity = tracked?.Device.Identity;
            if (identity is not null && observation.Hostname is not null)
                identity = DeviceIdentityMerger.Merge(identity, new DeviceIdentity
                { Hostname = observation.Hostname, HostnameSource = observation.IpAddress.Equals(result.Network.LocalIpv4)
                    ? DeviceNameSource.LocalComputer : DeviceNameSource.ReverseDns });
            var device = new NetworkDevice(observation.IpAddress, mac ?? tracked?.Device.MacAddress,
                identity?.Hostname ?? observation.Hostname ?? tracked?.Device.Hostname, observation.Latency, DeviceState.Online,
                firstSeen, lastSeen, Equals(observation.IpAddress, result.Network.Gateway),
                observation.IpAddress.Equals(result.Network.LocalIpv4), observation.Evidence)
            { Identity = identity, IsIdentityResolving = tracked?.Device.IsIdentityResolving ?? false };
            if (tracked is null) { tracked = new TrackedDevice(device); _devices.Add(tracked); }
            else { tracked.Device = device; tracked.MissedScans = 0; }
            seen.Add(tracked);
        }
        foreach (var tracked in _devices.Where(d => !seen.Contains(d)))
        {
            if (result.HasReliableAbsence) tracked.MissedScans = Math.Min(offlineAfterMissedScans, tracked.MissedScans + 1);
            tracked.Device = tracked.Device with
            {
                State = tracked.MissedScans >= offlineAfterMissedScans ? DeviceState.Offline : DeviceState.Unknown,
                Latency = null, Evidence = DeviceEvidence.None
            };
        }
        return Snapshot();
    }

    public IReadOnlyList<NetworkDevice> Snapshot() => Array.AsReadOnly(_devices.Select(d => d.Device).OrderBy(d => SubnetCalculator.ToUInt32(d.IpAddress))
            .ThenBy(d => d.FirstSeen).ToArray());

    public IReadOnlyList<NetworkDevice> SetResolving(bool resolving)
    {
        foreach (var tracked in _devices)
            tracked.Device = tracked.Device with { IsIdentityResolving = resolving && tracked.Device.State == DeviceState.Online };
        return Snapshot();
    }

    public IReadOnlyList<NetworkDevice> Enrich(NetworkDevice expected, DeviceIdentity identity, bool isComplete = false)
    {
        // An old response must not name a different device that has since acquired the same IP.
        var tracked = _devices.FirstOrDefault(d => d.Device.IpAddress.Equals(expected.IpAddress) &&
            Equals(d.Device.MacAddress, expected.MacAddress) && d.Device.FirstSeen == expected.FirstSeen);
        if (tracked is not null)
        {
            var merged = DeviceIdentityMerger.Merge(tracked.Device.Identity, identity);
            tracked.Device = tracked.Device with { Identity = merged, Hostname = merged.Hostname ?? tracked.Device.Hostname,
                IsIdentityResolving = !isComplete && tracked.Device.IsIdentityResolving };
        }
        return Snapshot();
    }

    public static bool ValidMac(PhysicalAddress? address)
    {
        if (address is null) return false;
        var bytes = address.GetAddressBytes();
        return bytes.Length == 6 && (bytes[0] & 1) == 0 && bytes.Any(b => b != 0);
    }

    private sealed class TrackedDevice(NetworkDevice device)
    {
        public NetworkDevice Device { get; set; } = device;
        public int MissedScans { get; set; }
    }
}
