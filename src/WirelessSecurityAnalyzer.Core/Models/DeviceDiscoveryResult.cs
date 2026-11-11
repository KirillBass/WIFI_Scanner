using System.Net;
using System.Net.NetworkInformation;
using WirelessSecurityAnalyzer.Core.Network;

namespace WirelessSecurityAnalyzer.Core.Models;

public sealed record DeviceDiscoveryResult(LocalNetworkInfo Network,
    IReadOnlyList<NetworkDeviceObservation> Observations, DateTimeOffset StartedAt, DateTimeOffset CompletedAt,
    long ProbedAddressCount, long RespondingAddressCount, bool HasReliableAbsence, string? Warning)
{
    public DeviceDiscoveryProgress? Progress { get; init; }
    public Guid RunId { get; init; }
    public Guid SessionId { get; init; }
    public bool IsCancelled => Progress?.Stage == DeviceDiscoveryStage.Cancelled;
}

public enum DeviceDiscoveryStage { Probe, NeighborMerge, HostnameResolution, Completed, Priority, Subnet, Cancelled, Error }
public sealed record DeviceDiscoveryProgress(DeviceDiscoveryStage Stage, long Probed, long Total, int Found)
{
    public int Active { get; init; }
    public TimeSpan Elapsed { get; init; }
}

public enum DeviceDiscoveryEventKind { DeviceFound, DeviceUpdated, AddressChecked, ProgressChanged, StageChanged, Completed, Cancelled, Error }
public sealed record DeviceDiscoveryContext(Guid RunId, Guid SessionId, IReadOnlyList<NetworkDevice> KnownDevices);
public sealed record DeviceDiscoveryEvent(Guid RunId, Guid SessionId, DeviceDiscoveryEventKind Kind)
{
    public NetworkDeviceObservation? Observation { get; init; }
    public IPAddress? CheckedAddress { get; init; }
    public bool HasReliableAbsence { get; init; }
    public DeviceDiscoveryProgress? Progress { get; init; }
    public DeviceDiscoveryResult? Result { get; init; }
    public NetworkDiscoveryException? Error { get; init; }
}

// Values follow NL_NEIGHBOR_STATE, but native structs stay in Windows Infrastructure.
public enum NeighborState { Unreachable, Incomplete, Probe, Delay, Stale, Reachable, Permanent }
public sealed record NeighborEntry(IPAddress IpAddress, PhysicalAddress? MacAddress,
    int InterfaceIndex, NeighborState State, bool IsUnreachable, uint ReachabilityTime);

public sealed record HostProbeResult(bool Replied, TimeSpan? Latency, bool RouteMatches = true, bool HadError = false);

public sealed record DeviceMonitorSnapshot(long Version, LocalNetworkInfo? Network,
    IReadOnlyList<NetworkDevice> Devices, bool IsMonitoring, bool IsDiscovering, TimeSpan Interval,
    DeviceDiscoveryProgress? Progress, DateTimeOffset? LastCompletedAt,
    NetworkDiscoveryException? Error, string? Warning)
{
    public bool IsResolvingIdentities { get; init; }
    public Guid RunId { get; init; }
    public Guid SessionId { get; init; }
}
