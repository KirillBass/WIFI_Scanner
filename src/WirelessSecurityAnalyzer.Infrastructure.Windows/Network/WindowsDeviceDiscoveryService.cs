using System.Collections.Concurrent;
using System.Diagnostics;
using System.Net;
using Serilog;
using WirelessSecurityAnalyzer.Core.Interfaces;
using WirelessSecurityAnalyzer.Core.Models;
using WirelessSecurityAnalyzer.Core.Network;

namespace WirelessSecurityAnalyzer.Infrastructure.Windows.Network;

/// <summary>One bounded discovery cycle; all OS operations are injected and independently testable.</summary>
public sealed class WindowsDeviceDiscoveryService(ILocalNetworkService networks, INeighborTableReader neighbors,
    IHostProbe probe, IHostnameResolver hostnames, ILogger logger, TimeProvider? timeProvider = null) : IDeviceDiscoveryService
{
    private readonly SemaphoreSlim _cycleGate = new(1, 1);
    private readonly TimeProvider _clock = timeProvider ?? TimeProvider.System;

    public async Task<DeviceDiscoveryResult> DiscoverAsync(LocalNetworkInfo network, DeviceDiscoveryOptions options,
        CancellationToken cancellationToken = default, IProgress<DeviceDiscoveryProgress>? progress = null)
    {
        ArgumentNullException.ThrowIfNull(network);
        ArgumentNullException.ThrowIfNull(options);
        options.Validate();
        var subnet = network.Subnet;
        subnet.EnsureSweepAllowed(options.MaxAutoHostCount);
        if (!subnet.ContainsHost(network.LocalIpv4))
            throw new NetworkDiscoveryException(NetworkDiscoveryError.NoInterface, "Interface has no usable IPv4 host address.");
        await _cycleGate.WaitAsync(cancellationToken).ConfigureAwait(false);
        try
        {
            await EnsureContextAsync(network, cancellationToken).ConfigureAwait(false);
            var started = _clock.GetUtcNow();
            var warnings = new List<string>();
            var before = await ReadNeighborsAsync(network, warnings, cancellationToken).ConfigureAwait(false);
            var observations = new ConcurrentDictionary<IPAddress, NetworkDeviceObservation>();
            observations[network.LocalIpv4] = new(network.LocalIpv4, network.LocalMacAddress, Environment.MachineName,
                null, DeviceEvidence.LocalMachine, started);
            var total = checked((int)subnet.HostCount - 1); // This PC is evidence, not an ICMP candidate.
            var probed = 0;
            var replied = 0;
            var skipped = 0;
            var failed = 0;
            var progressGate = new object();
            var lastProgress = Stopwatch.GetTimestamp();
            void Report(DeviceDiscoveryStage stage, bool force = false)
            {
                lock (progressGate)
                {
                    if (!force && Stopwatch.GetElapsedTime(lastProgress).TotalMilliseconds < 100) return;
                    lastProgress = Stopwatch.GetTimestamp();
                    try { progress?.Report(new(stage, probed, total, observations.Count)); }
                    catch (Exception exception) { logger.Debug(exception, "Device discovery progress subscriber failed"); }
                }
            }
            logger.Information("Device discovery started on {InterfaceId}: {Subnet}/{Prefix}; {CandidateCount} probes",
                network.InterfaceId, subnet.NetworkAddress, network.PrefixLength, total);
            Report(DeviceDiscoveryStage.Probe, true);
            await Parallel.ForEachAsync(subnet.EnumerateHosts(options.MaxAutoHostCount).Where(ip => !ip.Equals(network.LocalIpv4)),
                new ParallelOptions { MaxDegreeOfParallelism = options.MaxConcurrency, CancellationToken = cancellationToken },
                async (address, token) =>
                {
                    var reply = await probe.ProbeAsync(network, address, options.PingTimeoutMs, token).ConfigureAwait(false);
                    if (!reply.RouteMatches) Interlocked.Increment(ref skipped);
                    else if (reply.HadError) Interlocked.Increment(ref failed);
                    else if (reply.Replied)
                    {
                        Interlocked.Increment(ref replied);
                        observations[address] = new(address, null, null, reply.Latency,
                            DeviceEvidence.PingReply | (Equals(address, network.Gateway) ? DeviceEvidence.Gateway : DeviceEvidence.None),
                            _clock.GetUtcNow());
                    }
                    Interlocked.Increment(ref probed);
                    Report(DeviceDiscoveryStage.Probe);
                }).ConfigureAwait(false);
            cancellationToken.ThrowIfCancellationRequested();
            await EnsureContextAsync(network, cancellationToken).ConfigureAwait(false);
            Report(DeviceDiscoveryStage.NeighborMerge, true);
            var after = await ReadNeighborsAsync(network, warnings, cancellationToken).ConfigureAwait(false);
            var usableBefore = FilterNeighbors(before.Entries, network).ToDictionary(n => n.IpAddress);
            var current = FilterNeighbors(after.Succeeded ? after.Entries : before.Entries, network);
            foreach (var neighbor in current)
            {
                var hasPing = observations.TryGetValue(neighbor.IpAddress, out var observation);
                var changed = before.Succeeded && after.Succeeded && (!usableBefore.TryGetValue(neighbor.IpAddress, out var old) ||
                    !Equals(old.MacAddress, neighbor.MacAddress));
                // A cached Stale/Permanent address is not proof of presence on every monitoring cycle.
                var fresh = !neighbor.IsUnreachable && (neighbor.State == NeighborState.Reachable ||
                    (changed && neighbor.State is NeighborState.Stale or NeighborState.Delay or NeighborState.Probe));
                if (!hasPing && !fresh) continue;
                var evidence = observation?.Evidence ?? DeviceEvidence.None;
                if (fresh) evidence |= DeviceEvidence.NeighborEntry;
                if (Equals(neighbor.IpAddress, network.Gateway)) evidence |= DeviceEvidence.Gateway;
                observations[neighbor.IpAddress] = new(neighbor.IpAddress, neighbor.MacAddress ?? observation?.MacAddress,
                    observation?.Hostname, observation?.Latency, evidence, observation?.ObservedAt ?? _clock.GetUtcNow());
            }
            if (skipped > 0) warnings.Add($"Маршрут {skipped} адресов проходит через другой интерфейс или недоступен; эти адреса не опрашивались.");
            if (failed > 0) warnings.Add($"Ошибки ICMP при проверке {failed} адресов; статусы отсутствующих устройств не подтверждены.");
            if (total > 0 && failed == total)
                throw new NetworkDiscoveryException(NetworkDiscoveryError.ProbeFailed, "Every ICMP operation failed.");

            if (options.ResolveHostnames)
            {
                Report(DeviceDiscoveryStage.HostnameResolution, true);
                await Parallel.ForEachAsync(observations.Values.Where(o => !o.IpAddress.Equals(network.LocalIpv4)),
                    new ParallelOptions { MaxDegreeOfParallelism = options.HostnameConcurrency, CancellationToken = cancellationToken },
                    async (observation, token) =>
                    {
                        using var timeout = CancellationTokenSource.CreateLinkedTokenSource(token);
                        timeout.CancelAfter(options.HostnameTimeoutMs);
                        try
                        {
                            var hostname = await hostnames.ResolveAsync(network, observation.IpAddress, options.HostnameTimeoutMs, timeout.Token)
                                .WaitAsync(timeout.Token).ConfigureAwait(false);
                            if (!string.IsNullOrWhiteSpace(hostname)) observations[observation.IpAddress] = observation with { Hostname = hostname };
                        }
                        catch (OperationCanceledException) when (token.IsCancellationRequested) { throw; }
                        catch (Exception exception) { logger.Debug(exception, "Optional hostname lookup failed for {Address}", observation.IpAddress); }
                    }).ConfigureAwait(false);
            }
            await EnsureContextAsync(network, cancellationToken).ConfigureAwait(false);
            cancellationToken.ThrowIfCancellationRequested();
            var result = new DeviceDiscoveryResult(network,
                Array.AsReadOnly(observations.Values.OrderBy(o => SubnetCalculator.ToUInt32(o.IpAddress)).ToArray()),
                started, _clock.GetUtcNow(), probed - skipped, replied,
                after.Succeeded && failed == 0 && skipped == 0, warnings.Count == 0 ? null : string.Join(" ", warnings));
            Report(DeviceDiscoveryStage.Completed, true);
            logger.Information("Device discovery completed: {DeviceCount} confirmed devices, {ReplyCount} ICMP replies", result.Observations.Count, replied);
            return result;
        }
        finally { _cycleGate.Release(); }
    }

    private async Task EnsureContextAsync(LocalNetworkInfo network, CancellationToken token)
    {
        if (!await networks.IsCurrentAsync(network, token).ConfigureAwait(false))
            throw new NetworkDiscoveryException(NetworkDiscoveryError.ContextChanged, "Selected interface or IPv4 network changed during discovery.");
    }

    private async Task<(IReadOnlyList<NeighborEntry> Entries, bool Succeeded)> ReadNeighborsAsync(
        LocalNetworkInfo network, List<string> warnings, CancellationToken token)
    {
        try { return (await neighbors.ReadAsync(network, token).ConfigureAwait(false), true); }
        catch (OperationCanceledException) when (token.IsCancellationRequested) { throw; }
        catch (Exception exception)
        {
            logger.Warning(exception, "Neighbor table read failed on {InterfaceId}", network.InterfaceId);
            warnings.Add("Таблица соседей недоступна; MAC и обнаружение устройств без ICMP могут быть неполными.");
            return (Array.Empty<NeighborEntry>(), false);
        }
    }

    private static IEnumerable<NeighborEntry> FilterNeighbors(IReadOnlyList<NeighborEntry> entries, LocalNetworkInfo network) =>
        entries.Where(n => n.InterfaceIndex == network.InterfaceIndex && network.Subnet.ContainsHost(n.IpAddress) &&
            DeviceStateTracker.ValidMac(n.MacAddress)).GroupBy(n => n.IpAddress)
            .Select(g => g.OrderByDescending(n => n.State == NeighborState.Reachable && !n.IsUnreachable).First());
}
