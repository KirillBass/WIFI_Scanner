using System.Net;
using System.Net.NetworkInformation;

namespace WirelessSecurityAnalyzer.Core.Models;

public enum DeviceState { Online, Offline, Unknown }

[Flags]
public enum DeviceEvidence { None = 0, PingReply = 1, NeighborEntry = 2, LocalMachine = 4, Gateway = 8 }

public sealed record NetworkDevice(IPAddress IpAddress, PhysicalAddress? MacAddress, string? Hostname,
    TimeSpan? Latency, DeviceState State, DateTimeOffset FirstSeen, DateTimeOffset LastSeen,
    bool IsGateway, bool IsLocalMachine, DeviceEvidence Evidence)
{
    public DeviceIdentity? Identity { get; init; }
    public bool IsIdentityResolving { get; init; }
    public string? FriendlyName => Identity?.FriendlyName;
    public string? Vendor => Identity?.Vendor;
    public string? ModelName => Identity?.ModelName;
    public string? DeviceType => Identity?.DeviceType;
    public DeviceNameSource NameSource => Identity?.NameSource ?? DeviceNameSource.None;
    public DateTimeOffset? IdentityLastUpdated => Identity?.LastUpdated;
    public string DisplayName => Identity?.DisplayName is { } name && name != "—" ? name : !string.IsNullOrWhiteSpace(Hostname) ? Hostname : "—";
}

public sealed record NetworkDeviceObservation(IPAddress IpAddress, PhysicalAddress? MacAddress,
    string? Hostname, TimeSpan? Latency, DeviceEvidence Evidence, DateTimeOffset ObservedAt)
{
    public bool IsConfirmed => (Evidence & (DeviceEvidence.PingReply | DeviceEvidence.NeighborEntry | DeviceEvidence.LocalMachine)) != 0;
}
