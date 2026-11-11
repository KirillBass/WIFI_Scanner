using System.Diagnostics;
using System.Net;
using System.Threading.Channels;
using Serilog;
using WirelessSecurityAnalyzer.Core.Interfaces;
using WirelessSecurityAnalyzer.Core.Models;
using WirelessSecurityAnalyzer.Core.Network;

namespace WirelessSecurityAnalyzer.Infrastructure.Windows.Network;

/// <summary>One serialized cycle, two lazy stages, and a bounded pool shared by all candidates.</summary>
public sealed class WindowsDeviceDiscoveryService(ILocalNetworkService networks, INeighborTableReader neighbors,
    IHostProbe probe, IHostnameResolver hostnames, ILogger logger, TimeProvider? timeProvider = null)
    : IStreamingDeviceDiscoveryService
{
    private readonly SemaphoreSlim _cycleGate = new(1, 1);
    private readonly TimeProvider _clock = timeProvider ?? TimeProvider.System;

    public async Task<DeviceDiscoveryResult> DiscoverAsync(LocalNetworkInfo network, DeviceDiscoveryOptions options,
        CancellationToken cancellationToken = default, IProgress<DeviceDiscoveryProgress>? progress = null)
    {
        var result = await RunAsync(network, options, new(Guid.NewGuid(), Guid.Empty, []),
            update => { if (update.Progress is { } p) progress?.Report(p); }, cancellationToken).ConfigureAwait(false);
        if (result.IsCancelled) throw new OperationCanceledException(cancellationToken);
        return result;
    }

    // Production names are enriched independently by DeviceMonitorService, even if a caller enables legacy DNS.
    public Task<DeviceDiscoveryResult> DiscoverStreamingAsync(LocalNetworkInfo network, DeviceDiscoveryOptions options,
        DeviceDiscoveryContext context, Action<DeviceDiscoveryEvent> publish, CancellationToken cancellationToken = default) =>
        RunAsync(network, options with { ResolveHostnames = false }, context, publish, cancellationToken);

    private async Task<DeviceDiscoveryResult> RunAsync(LocalNetworkInfo network, DeviceDiscoveryOptions options,
        DeviceDiscoveryContext context, Action<DeviceDiscoveryEvent> publish, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(network);
        ArgumentNullException.ThrowIfNull(options);
        options.Validate();
        if (!network.Subnet.ContainsHost(network.LocalIpv4))
            throw new NetworkDiscoveryException(NetworkDiscoveryError.NoInterface, "Interface has no usable IPv4 host address.");
        await _cycleGate.WaitAsync(cancellationToken).ConfigureAwait(false);
        using var cycle = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
        var token = cycle.Token;
        var gate = new object();
        var observations = new Dictionary<IPAddress, NetworkDeviceObservation>();
        var warnings = new HashSet<string>();
        var started = _clock.GetUtcNow();
        var timer = Stopwatch.StartNew();
        var total = checked((long)network.Subnet.UsableHostCount);
        long checkedCount = 0, replies = 0, skipped = 0, failed = 0;
        var active = 0;
        var stage = DeviceDiscoveryStage.Priority;
        long lastProgress = 0;
        NetworkDiscoveryException? contextError = null;
        Task watcher = Task.CompletedTask;
        var neighborReadFailed = false;
        var terminal = false;

        void Emit(DeviceDiscoveryEvent update)
        {
            // Callback ordering is also the publication boundary for counters and observations.
            lock (gate)
            {
                if (terminal) return;
                terminal = update.Kind is DeviceDiscoveryEventKind.Completed or DeviceDiscoveryEventKind.Cancelled or DeviceDiscoveryEventKind.Error;
                try { publish(update); }
                catch (Exception exception) { logger.Error(exception, "Device discovery subscriber failed"); }
            }
        }
        DeviceDiscoveryEvent Event(DeviceDiscoveryEventKind kind) => new(context.RunId, context.SessionId, kind);
        DeviceDiscoveryProgress Progress() => new(stage, Interlocked.Read(ref checkedCount), total, observations.Count)
        { Active = Volatile.Read(ref active), Elapsed = timer.Elapsed };
        void Report(bool force = false, bool stageChanged = false)
        {
            lock (gate)
            {
                if (!force && timer.ElapsedMilliseconds - lastProgress < 100) return;
                lastProgress = timer.ElapsedMilliseconds;
                Emit(Event(stageChanged ? DeviceDiscoveryEventKind.StageChanged : DeviceDiscoveryEventKind.ProgressChanged)
                    with { Progress = Progress() });
            }
        }
        void Observe(NetworkDeviceObservation observation)
        {
            token.ThrowIfCancellationRequested();
            lock (gate)
            {
                var kind = observations.ContainsKey(observation.IpAddress)
                    ? DeviceDiscoveryEventKind.DeviceUpdated : DeviceDiscoveryEventKind.DeviceFound;
                observations[observation.IpAddress] = observation;
                Emit(Event(kind) with { Observation = observation });
            }
        }
        async Task<(Dictionary<IPAddress, NeighborEntry> Entries, bool Succeeded)> ReadNeighborsAsync(CancellationToken ct)
        {
            try
            {
                var entries = await neighbors.ReadAsync(network, ct).ConfigureAwait(false);
                return (entries.Where(n => n.InterfaceIndex == network.InterfaceIndex && network.Subnet.ContainsHost(n.IpAddress))
                    .GroupBy(n => n.IpAddress).ToDictionary(g => g.Key,
                        g => g.OrderByDescending(n => n.State == NeighborState.Reachable && !n.IsUnreachable).First()), true);
            }
            catch (OperationCanceledException) when (ct.IsCancellationRequested) { throw; }
            catch (Exception exception)
            {
                lock (gate)
                {
                    if (!neighborReadFailed) logger.Warning(exception, "Neighbor table unavailable on {InterfaceId}", network.InterfaceId);
                    neighborReadFailed = true;
                    warnings.Add("Таблица соседей недоступна; MAC и обнаружение устройств без ICMP могут быть неполными.");
                }
                return ([], false);
            }
        }
        DeviceDiscoveryResult Result()
        {
            lock (gate)
            {
                if (skipped > 0) warnings.Add($"Маршрут {skipped} адресов проходит через другой интерфейс или недоступен; эти адреса не опрашивались.");
                if (failed > 0) warnings.Add($"Ошибки ICMP при проверке {failed} адресов; статусы отсутствующих устройств не подтверждены.");
                return new(network, Array.AsReadOnly(observations.Values.OrderBy(o => SubnetCalculator.ToUInt32(o.IpAddress)).ToArray()),
                    started, _clock.GetUtcNow(), Math.Max(0, checkedCount - 1 - skipped), replies,
                    stage == DeviceDiscoveryStage.Completed && !neighborReadFailed && failed == 0 && skipped == 0,
                    warnings.Count == 0 ? null : string.Join(" ", warnings))
                { RunId = context.RunId, SessionId = context.SessionId, Progress = Progress() };
            }
        }
        try
        {
            await EnsureContextAsync(network, token).ConfigureAwait(false);
            logger.Information("Discovery {RunId} started; session {SessionId}, {InterfaceId}, {Subnet}/{Prefix}, hosts {Total}, workers {Concurrency}",
                context.RunId, context.SessionId, network.InterfaceId, network.NetworkAddress, network.PrefixLength, total, options.MaxConcurrency);
            Observe(new(network.LocalIpv4, network.LocalMacAddress, Environment.MachineName, null, DeviceEvidence.LocalMachine, started));
            Interlocked.Increment(ref checkedCount);
            Report(true, true);
            watcher = WatchContextAsync();
            var baseline = await ReadNeighborsAsync(token).ConfigureAwait(false);
            var priority = new HashSet<IPAddress> { network.LocalIpv4 };
            var candidates = new List<IPAddress>();
            void AddPriority(IPAddress? address)
            {
                token.ThrowIfCancellationRequested();
                if (address is not null && network.Subnet.ContainsHost(address) && priority.Add(address)) candidates.Add(address);
            }
            AddPriority(network.Gateway);
            foreach (var address in baseline.Entries.Keys) AddPriority(address);
            foreach (var device in context.KnownDevices) AddPriority(device.IpAddress);

            // One post-probe table read can serve probes that finished before that read started.
            // The cache contains the OS table, never the entire subnet or a task for every IP.
            using var tableGate = new SemaphoreSlim(1, 1);
            long snapshotStarted = 0;
            (Dictionary<IPAddress, NeighborEntry> Entries, bool Succeeded) snapshot = ([], false);
            async Task<(Dictionary<IPAddress, NeighborEntry> Entries, bool Succeeded)> AfterProbeAsync(long finished, CancellationToken ct)
            {
                await tableGate.WaitAsync(ct).ConfigureAwait(false);
                try
                {
                    if (snapshotStarted < finished)
                    {
                        var readStarted = Stopwatch.GetTimestamp();
                        snapshot = await ReadNeighborsAsync(ct).ConfigureAwait(false);
                        snapshotStarted = readStarted;
                    }
                    return snapshot;
                }
                finally { tableGate.Release(); }
            }
            async Task CheckAsync(IPAddress address, CancellationToken ct)
            {
                Interlocked.Increment(ref active);
                try
                {
                    logger.Debug("Discovery {RunId} checking {Address}", context.RunId, address);
                    var reply = await probe.ProbeAsync(network, address, options.PingTimeoutMs, ct).ConfigureAwait(false);
                    ct.ThrowIfCancellationRequested();
                    Interlocked.Increment(ref checkedCount);
                    if (!reply.RouteMatches) Interlocked.Increment(ref skipped);
                    else if (reply.HadError) Interlocked.Increment(ref failed);
                    else
                    {
                        if (reply.Replied)
                        {
                            Interlocked.Increment(ref replies);
                            // Publish before reading ARP or starting any name resolution.
                            Observe(new(address, null, null, reply.Latency, DeviceEvidence.PingReply |
                                (Equals(address, network.Gateway) ? DeviceEvidence.Gateway : DeviceEvidence.None), _clock.GetUtcNow()));
                        }
                        var after = await AfterProbeAsync(Stopwatch.GetTimestamp(), ct).ConfigureAwait(false);
                        after.Entries.TryGetValue(address, out var neighbor);
                        baseline.Entries.TryGetValue(address, out var old);
                        var valid = neighbor is not null && !neighbor.IsUnreachable && DeviceStateTracker.ValidMac(neighbor.MacAddress);
                        // ReachabilityTime is not an observation timestamp. Its change alone is never proof.
                        var fresh = baseline.Succeeded && after.Succeeded && valid &&
                            (old is null || !Equals(old.MacAddress, neighbor!.MacAddress) ||
                             neighbor!.State == NeighborState.Reachable &&
                             (old.State != NeighborState.Reachable || old.IsUnreachable)) &&
                            neighbor!.State is NeighborState.Reachable or NeighborState.Stale or NeighborState.Delay or NeighborState.Probe;
                        if (reply.Replied && valid || fresh)
                            Observe(new(address, neighbor!.MacAddress, null, reply.Latency,
                                (reply.Replied ? DeviceEvidence.PingReply : DeviceEvidence.None) |
                                (fresh ? DeviceEvidence.NeighborEntry : DeviceEvidence.None) |
                                (Equals(address, network.Gateway) ? DeviceEvidence.Gateway : DeviceEvidence.None), _clock.GetUtcNow()));
                        else if (!reply.Replied)
                            Emit(Event(DeviceDiscoveryEventKind.AddressChecked) with { CheckedAddress = address,
                                HasReliableAbsence = baseline.Succeeded && after.Succeeded &&
                                    !(valid && neighbor!.State is NeighborState.Reachable or NeighborState.Permanent) });
                    }
                }
                finally { Interlocked.Decrement(ref active); Report(); }
            }
            async Task RunStageAsync(IEnumerable<IPAddress> addresses)
            {
                using var pool = CancellationTokenSource.CreateLinkedTokenSource(token);
                var channel = Channel.CreateBounded<IPAddress>(new BoundedChannelOptions(options.MaxConcurrency * 2)
                { SingleWriter = true, FullMode = BoundedChannelFullMode.Wait });
                async Task ProduceAsync()
                {
                    try
                    {
                        foreach (var address in addresses)
                        {
                            pool.Token.ThrowIfCancellationRequested();
                            await channel.Writer.WriteAsync(address, pool.Token).ConfigureAwait(false);
                        }
                        channel.Writer.TryComplete();
                    }
                    catch (Exception exception) { channel.Writer.TryComplete(exception); pool.Cancel(); throw; }
                }
                async Task ConsumeAsync()
                {
                    try
                    {
                        await foreach (var address in channel.Reader.ReadAllAsync(pool.Token).ConfigureAwait(false))
                            await CheckAsync(address, pool.Token).ConfigureAwait(false);
                    }
                    catch { pool.Cancel(); throw; }
                }
                // Fixed number of tasks; the producer can be at most two worker batches ahead.
                var tasks = Enumerable.Range(0, options.MaxConcurrency).Select(_ => Task.Run(ConsumeAsync, CancellationToken.None)).ToList();
                tasks.Add(Task.Run(ProduceAsync, CancellationToken.None));
                await Task.WhenAll(tasks).ConfigureAwait(false);
            }
            await RunStageAsync(candidates).ConfigureAwait(false);
            token.ThrowIfCancellationRequested();
            stage = DeviceDiscoveryStage.Subnet;
            Report(true, true);
            IEnumerable<IPAddress> RemainingAddresses()
            {
                foreach (var address in network.Subnet.EnumerateHosts())
                {
                    token.ThrowIfCancellationRequested();
                    if (!priority.Contains(address)) yield return address;
                }
            }
            await RunStageAsync(RemainingAddresses()).ConfigureAwait(false);
            await EnsureContextAsync(network, token).ConfigureAwait(false);
            if (checkedCount > 1 && failed == checkedCount - 1)
                throw new NetworkDiscoveryException(NetworkDiscoveryError.ProbeFailed, "Every ICMP operation failed.");
            if (options.ResolveHostnames)
            {
                stage = DeviceDiscoveryStage.HostnameResolution;
                Report(true, true);
                await Parallel.ForEachAsync(observations.Values.Where(o => !o.IpAddress.Equals(network.LocalIpv4)).ToArray(),
                    new ParallelOptions { MaxDegreeOfParallelism = options.HostnameConcurrency, CancellationToken = token },
                    async (observation, ct) =>
                    {
                        using var timeout = CancellationTokenSource.CreateLinkedTokenSource(ct);
                        timeout.CancelAfter(options.HostnameTimeoutMs);
                        try
                        {
                            var name = await hostnames.ResolveAsync(network, observation.IpAddress, options.HostnameTimeoutMs, timeout.Token)
                                .WaitAsync(timeout.Token).ConfigureAwait(false);
                            if (!string.IsNullOrWhiteSpace(name)) Observe(observation with { Hostname = name });
                        }
                        catch (OperationCanceledException) when (ct.IsCancellationRequested) { throw; }
                        catch (Exception exception) { logger.Debug(exception, "Optional hostname lookup failed for {Address}", observation.IpAddress); }
                    }).ConfigureAwait(false);
            }
            token.ThrowIfCancellationRequested();
            stage = DeviceDiscoveryStage.Completed;
            var result = Result();
            Emit(Event(DeviceDiscoveryEventKind.Completed) with { Result = result, Progress = result.Progress });
            logger.Information("Discovery {RunId} completed; checked {Checked}/{Total}, found {Found}, elapsed {Elapsed}",
                context.RunId, checkedCount, total, observations.Count, timer.Elapsed);
            return result;
        }
        catch (OperationCanceledException) when (token.IsCancellationRequested && contextError is null)
        {
            stage = DeviceDiscoveryStage.Cancelled;
            var result = Result();
            Emit(Event(DeviceDiscoveryEventKind.Cancelled) with { Result = result, Progress = result.Progress });
            logger.Information("Discovery {RunId} cancelled; checked {Checked}/{Total}, found {Found}, elapsed {Elapsed}",
                context.RunId, checkedCount, total, observations.Count, timer.Elapsed);
            return result;
        }
        catch (Exception exception)
        {
            stage = DeviceDiscoveryStage.Error;
            var error = contextError ?? exception as NetworkDiscoveryException ??
                new NetworkDiscoveryException(NetworkDiscoveryError.Unexpected, "Device discovery failed.", exception);
            Emit(Event(DeviceDiscoveryEventKind.Error) with { Error = error, Result = Result(), Progress = Progress() });
            throw error;
        }
        finally
        {
            await cycle.CancelAsync().ConfigureAwait(false);
            await watcher.ConfigureAwait(false);
            _cycleGate.Release();
        }

        async Task WatchContextAsync()
        {
            try
            {
                while (true)
                {
                    await Task.Delay(TimeSpan.FromSeconds(1), _clock, token).ConfigureAwait(false);
                    await EnsureContextAsync(network, token).ConfigureAwait(false);
                    Report();
                }
            }
            catch (OperationCanceledException) when (token.IsCancellationRequested) { }
            catch (Exception exception)
            {
                contextError = exception as NetworkDiscoveryException ??
                    new NetworkDiscoveryException(NetworkDiscoveryError.ContextChanged, "Selected network changed.", exception);
                await cycle.CancelAsync().ConfigureAwait(false);
            }
        }
    }

    private async Task EnsureContextAsync(LocalNetworkInfo network, CancellationToken token)
    {
        if (!await networks.IsCurrentAsync(network, token).ConfigureAwait(false))
            throw new NetworkDiscoveryException(NetworkDiscoveryError.ContextChanged, "Selected interface or IPv4 network changed during discovery.");
    }
}
