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
            var device = new NetworkDevice(observation.IpAddress, mac ?? tracked?.Device.MacAddress,
                observation.Hostname ?? tracked?.Device.Hostname, observation.Latency, DeviceState.Online,
                firstSeen, lastSeen, Equals(observation.IpAddress, result.Network.Gateway),
                observation.IpAddress.Equals(result.Network.LocalIpv4), observation.Evidence);
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
        return Array.AsReadOnly(_devices.Select(d => d.Device).OrderBy(d => SubnetCalculator.ToUInt32(d.IpAddress))
            .ThenBy(d => d.FirstSeen).ToArray());
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
