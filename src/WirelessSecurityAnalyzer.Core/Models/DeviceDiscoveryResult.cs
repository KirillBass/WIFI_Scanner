using System.Net;
using System.Net.NetworkInformation;
using WirelessSecurityAnalyzer.Core.Network;

namespace WirelessSecurityAnalyzer.Core.Models;

public sealed record DeviceDiscoveryResult(LocalNetworkInfo Network,
    IReadOnlyList<NetworkDeviceObservation> Observations, DateTimeOffset StartedAt, DateTimeOffset CompletedAt,
    int ProbedAddressCount, int RespondingAddressCount, bool HasReliableAbsence, string? Warning);

public enum DeviceDiscoveryStage { Probe, NeighborMerge, HostnameResolution, Completed }
public sealed record DeviceDiscoveryProgress(DeviceDiscoveryStage Stage, int Probed, int Total, int Found);

// Values follow NL_NEIGHBOR_STATE, but native structs stay in Windows Infrastructure.
public enum NeighborState { Unreachable, Incomplete, Probe, Delay, Stale, Reachable, Permanent }
public sealed record NeighborEntry(IPAddress IpAddress, PhysicalAddress? MacAddress,
    int InterfaceIndex, NeighborState State, bool IsUnreachable, uint ReachabilityTime);

public sealed record HostProbeResult(bool Replied, TimeSpan? Latency, bool RouteMatches = true, bool HadError = false);

public sealed record DeviceMonitorSnapshot(long Version, LocalNetworkInfo? Network,
    IReadOnlyList<NetworkDevice> Devices, bool IsMonitoring, bool IsDiscovering, TimeSpan Interval,
    DeviceDiscoveryProgress? Progress, DateTimeOffset? LastCompletedAt,
    NetworkDiscoveryException? Error, string? Warning);
