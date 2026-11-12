using System.Diagnostics;
using System.Net;
using Serilog;
using WirelessSecurityAnalyzer.Core.Interfaces;
using WirelessSecurityAnalyzer.Core.Models;
using WirelessSecurityAnalyzer.Core.NetworkAudit;
using WirelessSecurityAnalyzer.Core.Network;

namespace WirelessSecurityAnalyzer.Infrastructure.Windows.NetworkAudit;

/// <summary>Owns a single immutable target snapshot and a bounded, lazy work queue.</summary>
public sealed class NetworkAuditService : INetworkAuditService, IDisposable
{
    private readonly INetworkSessionService _sessions;
    private readonly IDeviceMonitorService _devices;
    private readonly IHttpSiteDiscovery? _httpSites;
    private readonly ILocalTcpPortProvider? _localPorts;
    private string _localPortNote = "";
    private readonly ILocalNetworkService _networks;
    private readonly IPortScanner _scanner;
    private readonly IServiceDetectionEngine _engine;
    private readonly NetworkAuditOptions _options;
    private readonly ILogger _logger;
    private readonly object _gate = new();
    private readonly Dictionary<(IPAddress, int), AuditRow> _rows = [];
    private readonly Dictionary<IPAddress, HostWork> _hosts = [];
    private readonly TimeProvider _clock;
    private readonly DeviceDiscoveryOptions _discoveryOptions;
    private AuditSnapshot _current = AuditSnapshot.Empty;
    private CancellationTokenSource? _cancellation;
    private Task _run = Task.CompletedTask;
    private LocalNetworkInfo? _network;
    private AuditStage _stopStage = AuditStage.Cancelled;
    private bool _disposed;
    private long _version;
    private long _checked, _open, _closed, _timedOut, _unavailable, _errors, _identified, _total;
    private int _hostsCompleted, _hostsTotal;
    private readonly Stopwatch _watch = new();
    private long _lastPublishMs;
    public NetworkAuditService(INetworkSessionService sessions, IDeviceMonitorService devices, ILocalNetworkService networks,
        IPortScanner scanner, IServiceDetectionEngine engine, NetworkAuditOptions options, ILogger logger,
        DeviceDiscoveryOptions? discoveryOptions = null, TimeProvider? timeProvider = null, IHttpSiteDiscovery? httpSites = null,
        ILocalTcpPortProvider? localPorts = null)
    {
        _sessions = sessions; _devices = devices; _networks = networks; _scanner = scanner; _engine = engine;
        _options = options; _logger = logger; _sessions.Updated += SessionChanged;
        _clock = timeProvider ?? TimeProvider.System;
        _discoveryOptions = discoveryOptions ?? new() { ResolveHostnames = false };
        _httpSites = httpSites;
        _localPorts = localPorts;
    }
    public AuditSnapshot Current { get { lock (_gate) return _current; } }
    public event EventHandler<AuditSnapshot>? Updated;
    public Task RunAsync(AuditRequest request, CancellationToken cancellationToken = default)
    {
        AuditSnapshot started; Task run;
        lock (_gate)
        {
            ObjectDisposedException.ThrowIf(_disposed, this);
            if (!_run.IsCompleted) throw new InvalidOperationException("Аудит уже выполняется.");
            _options.Validate(request);
            var ports = PortScanProfiles.GetPorts(request);
            var session = _sessions.Current;
            if (!session.IsReadyForAudit || session.Network is null)
                throw new InvalidOperationException("Подключитесь к Wi-Fi и дождитесь получения IPv4.");
            var refresh = IsTargeted(request) && request.TargetAddress is null && NeedsDiscovery(session);
            if (refresh && (_devices.Current.IsDiscovering || _devices.Current.IsMonitoring))
                throw new InvalidOperationException("Остановите текущий поиск или мониторинг устройств перед обновлением целей аудита.");
            _localPortNote = "";
            var targets = refresh ? Array.Empty<AuditTarget>() : PrepareTargets(session, request);
            _network = session.Network!;
            _cancellation = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
            _stopStage = AuditStage.Cancelled; _rows.Clear();
            _checked = _open = _closed = _timedOut = _unavailable = _errors = _identified = 0;
            SetTargets(targets, ports);
            _watch.Restart(); _lastPublishMs = 0;
            _current = _current with { AuditId = Guid.NewGuid(), SessionId = session.SessionId, Stage = AuditStage.Preparing,
                IsRunning = true, Profile = request.Profile, TargetServicesOnly = IsTargeted(request),
                ScopeNote = refresh ? "Обновляется список узлов текущей подсети. TCP-проверки начнутся после обнаружения." : ScopeNote(request) };
            started = SnapshotLocked("Подготовка аудита текущей сети.");
            run = _run = RunCoreAsync(session, targets, ports, request, _current.AuditId, _cancellation);
        }
        Notify(started); return run;
    }
    private async Task RunCoreAsync(NetworkSession session, IReadOnlyList<AuditTarget> targets, IReadOnlyList<int> ports,
        AuditRequest request, Guid auditId, CancellationTokenSource cancellation)
    {
        await Task.Yield();
        var token = cancellation.Token; Task? watcher = null;
        _logger.Information("Network audit {AuditId} start: session {SessionId}, subnet {Subnet}, targets {Targets}, profile {Profile}, ports {Ports}, timeout {TimeoutMs}ms, concurrency {Concurrency}",
            auditId, session.SessionId, session.Subnet, targets.Count, request.Profile, ports.Count, request.ConnectTimeoutMs, request.Concurrency);
        try
        {
            if (!await _networks.IsCurrentAsync(session.Network!, token).ConfigureAwait(false))
            { MarkNetworkChanged(); token.ThrowIfCancellationRequested(); }
            CheckSession(session);
            watcher = WatchNetworkAsync(session, token);
            if (targets.Count == 0 && IsTargeted(request))
            {
                await _devices.DiscoverOnceAsync(session.Network!, _discoveryOptions with { ResolveHostnames = false }, token).ConfigureAwait(false);
                token.ThrowIfCancellationRequested();
                CheckSession(session);
                if (_devices.Current.Error?.Kind == NetworkDiscoveryError.ContextChanged)
                    throw new InvalidOperationException("Сеть изменилась во время обнаружения узлов.");
                targets = PrepareTargets(session, request);
                _logger.Information("Network audit {AuditId} discovery completed: {TargetCount} targets", auditId, targets.Count);
                lock (_gate)
                {
                    SetTargets(targets, ports);
                    _current = _current with { ScopeNote = ScopeNote(request) };
                }
            }
            lock (_gate) _current = _current with { Stage = AuditStage.Scanning };
            Publish(force: true);
            HostWork[] plans;
            lock (_gate) plans = targets.Select(t => _hosts[t.Address]).ToArray();
            var remaining = plans.ToDictionary(h => h.Target.Address, h => h.Ports.Count);
            IEnumerable<(AuditTarget Target, int Port)> Work()
            {
                var maximum = plans.Max(h => h.Ports.Count);
                for (var index = 0; index < maximum; index++)
                    foreach (var plan in plans)
                    {
                        token.ThrowIfCancellationRequested();
                        if (index < plan.Ports.Count) yield return (plan.Target, plan.Ports[index]);
                    }
            }
            await Parallel.ForEachAsync(Work(), new ParallelOptions { MaxDegreeOfParallelism = request.Concurrency, CancellationToken = token },
                async (work, ct) =>
                {
                    CheckSession(session); ct.ThrowIfCancellationRequested();
                    HostWork host;
                    lock (_gate)
                    {
                        if (_stopStage == AuditStage.NetworkChanged) throw new OperationCanceledException(ct);
                        host = _hosts[work.Target.Address]; host.Started = true; host.Summary = null;
                    }
                    Publish();
                    await using var connection = await _scanner.ConnectAsync(session.Network!, work.Target.Address, work.Port,
                        TimeSpan.FromMilliseconds(request.ConnectTimeoutMs), ct).ConfigureAwait(false);
                    ct.ThrowIfCancellationRequested();
                    if (connection.Result.State == PortState.Error)
                        _logger.Debug("TCP connect {Address}:{Port}: {Error}", work.Target.Address, work.Port, connection.Result.Error);
                    var inconclusive = connection.Result.State is PortState.Timeout or PortState.Unavailable or PortState.Error;
                    lock (_gate)
                    {
                        _checked++;
                        if (_checked == _total) _current = _current with { Stage = AuditStage.Detecting };
                        switch (connection.Result.State)
                        {
                            case PortState.Open:
                                _open++;
                                _rows[(work.Target.Address, work.Port)] = new(session.SessionId, work.Target, work.Port,
                                    ServiceIdentity.Unknown, _clock.GetUtcNow(), request.Profile) { AuditId = auditId }; break;
                            case PortState.Closed: _closed++; break;
                            case PortState.Timeout: _timedOut++; break;
                            case PortState.Unavailable: _unavailable++; break;
                            default: _errors++; break;
                        }
                    }
                    Publish(force: connection.Result.State == PortState.Open && Current.Progress.Open == 0);
                    if (connection.Result.State == PortState.Open)
                    {
                        ServiceIdentity identity;
                        try
                        {
                            identity = IsTargeted(request)
                                ? await _engine.DetectTargetedAsync(session.Network!, connection, ct).ConfigureAwait(false)
                                : await _engine.DetectAsync(session.Network!, connection, ct).ConfigureAwait(false);
                        }
                        catch (OperationCanceledException) { throw; }
                        catch (Exception ex)
                        {
                            _logger.Debug("Service detection {Address}:{Port}: {ErrorType}", work.Target.Address, work.Port, ex.GetType().Name);
                            identity = ServiceIdentity.Unknown;
                            lock (_gate) _errors++;
                        }
                        ct.ThrowIfCancellationRequested(); CheckSession(session);
                        lock (_gate)
                        {
                            if (identity.Confidence != ServiceConfidence.Unknown) _identified++;
                            _rows[(work.Target.Address, work.Port)] = _rows[(work.Target.Address, work.Port)] with
                                { Service = identity, DetectedAt = _clock.GetUtcNow() };
                            host.Summary = null;
                        }
                        inconclusive |= identity.Confidence is ServiceConfidence.Unknown or ServiceConfidence.Low or ServiceConfidence.Medium;
                        // A confirmed endpoint must be visible immediately, even while other hosts are still pending.
                        Publish(force: TargetServiceMatcher.IsConfirmed(identity));
                    }
                    lock (_gate)
                    {
                        host.Checked++;
                        if (inconclusive) host.InconclusivePorts.Add(work.Port);
                        host.LastChecked = _clock.GetUtcNow();
                        host.Summary = null;
                        if (--remaining[work.Target.Address] == 0) _hostsCompleted++;
                    }
                    Publish();
                    if (_httpSites is not null && connection.Result.State == PortState.Open)
                    {
                        AuditRow candidate;
                        lock (_gate) candidate = _rows[(work.Target.Address, work.Port)];
                        if (candidate.Protocol is "HTTP" or "Unknown")
                        {
                            // Release the detection socket before the pooled HTTP client opens its own connection.
                            await connection.DisposeAsync().ConfigureAwait(false);
                            lock (_gate) if (_checked == _total) _current = _current with { Stage = AuditStage.FindingSites };
                            await EnrichHttpAsync(session, candidate, ct).ConfigureAwait(false);
                        }
                    }
                }).ConfigureAwait(false);
            token.ThrowIfCancellationRequested(); CheckSession(session);
            lock (_gate) _current = _current with { Stage = AuditStage.Completed };
        }
        catch (OperationCanceledException)
        { lock (_gate) _current = _current with { Stage = _stopStage }; }
        catch (Exception ex)
        {
            _logger.Warning("Network audit failed: {ErrorType}", ex.GetType().Name);
            lock (_gate) _current = _current with { Stage = AuditStage.Failed, Message = "Не удалось выполнить аудит. Обновите устройства и повторите." };
        }
        finally
        {
            await cancellation.CancelAsync().ConfigureAwait(false);
            if (watcher is not null) await watcher.ConfigureAwait(false);
            AuditSnapshot finished;
            lock (_gate)
            {
                _watch.Stop();
                if (_stopStage == AuditStage.NetworkChanged || !Matches(session, _sessions.Current))
                { _rows.Clear(); _hosts.Clear(); _current = _current with { Stage = AuditStage.NetworkChanged }; }
                _current = _current with { IsRunning = false };
                finished = SnapshotLocked(StageMessage());
                _cancellation = null; cancellation.Dispose();
            }
            Notify(finished);
            _logger.Information("Network audit {AuditId} end: {Stage}, checked {Checked}/{Total}, open {Open}, identified {Identified}, elapsed {Elapsed}",
                finished.AuditId, finished.Stage, finished.Progress.Checked, finished.Progress.Total, finished.Progress.Open,
                finished.Progress.Identified, finished.Progress.Elapsed);
        }
    }
    private async Task EnrichHttpAsync(NetworkSession session, AuditRow candidate, CancellationToken token)
    {
        void Accept(IReadOnlyList<HttpSiteResult> sites)
        {
            lock (_gate)
            {
                if (_stopStage == AuditStage.NetworkChanged || !Matches(session, _sessions.Current) ||
                    _current.AuditId != candidate.AuditId || !_rows.TryGetValue((candidate.Target.Address, candidate.Port), out var row)) return;
                var current = sites.Where(s => s.SessionId == candidate.SessionId && s.AuditId == candidate.AuditId &&
                    s.Address.Equals(candidate.Target.Address) && s.Port == candidate.Port).ToArray();
                var confirmed = current.FirstOrDefault(s => s.HttpConfirmed);
                if (row.Protocol == "Unknown" && confirmed is not null)
                {
                    var (product, version) = ProbeIo.HttpProduct(confirmed.Server);
                    row = row with { Service = new("HTTP", product, version, ServiceConfidence.High,
                        confirmed.Evidence.Length > 0 ? confirmed.Evidence : $"HTTP GET: {confirmed.StatusCode} · {confirmed.Url}",
                        "HTTP подтверждён ограниченной проверкой страниц."), DetectedAt = _clock.GetUtcNow() };
                    _identified++;
                    _hosts[candidate.Target.Address].InconclusivePorts.Remove(candidate.Port);
                    _hosts[candidate.Target.Address].Summary = null;
                }
                _rows[(candidate.Target.Address, candidate.Port)] = row with { HttpSites = Array.AsReadOnly(current) };
            }
            Publish(force: true);
        }
        try { await _httpSites!.DiscoverAsync(session.Network!, candidate, Accept, token).ConfigureAwait(false); }
        catch (OperationCanceledException) { throw; }
        catch (Exception ex)
        {
            _logger.Debug("HTTP site discovery {Address}:{Port}: {ErrorType}", candidate.Address, candidate.Port, ex.GetType().Name);
            Accept([new(candidate.SessionId, candidate.AuditId, candidate.Target.Address, candidate.Port,
                new UriBuilder("http", candidate.Address, candidate.Port).Uri, candidate.Protocol, candidate.Product, "TCP-аудит")
                { State = HttpSiteState.ConnectionError, IsPartial = true, Message = "Ошибка HTTP-проверки: " + ex.GetType().Name + "." }]);
        }
    }
    private bool NeedsDiscovery(NetworkSession session)
    {
        var snapshot = _devices.Current;
        return snapshot.Network?.HasSameContext(session.Network!) != true || snapshot.Devices.Count == 0 ||
            snapshot.SessionId != Guid.Empty && snapshot.SessionId != session.SessionId ||
            _clock.GetUtcNow() - snapshot.Devices.Max(d => d.LastSeen) > _options.TargetDiscoveryMaxAge;
    }
    private string DiscoveryNote() => _devices.Current.Progress is { Stage: not DeviceDiscoveryStage.Completed } || _devices.Current.Error is not null
        ? "Использован частичный список обнаруженных узлов. Аудит охватывает только эти IP; непроверенные адреса подсети не оценивались."
        : "Проверяются обнаруженные узлы текущей подсети. Выводы относятся только к указанным TCP-портам.";
    private static bool IsTargeted(AuditRequest request) => request.TargetServicesOnly || request.Profile == PortProfile.Targeted;
    private string ScopeNote(AuditRequest request) => (request.TargetAddress is { } address ? $"Цель аудита: {address}. " : "") + DiscoveryNote() + _localPortNote;
    private IReadOnlyList<AuditTarget> PrepareTargets(NetworkSession session, AuditRequest request)
    {
        var targets = AuditTargets.Create(session, _devices.Current, request.IncludeLocal);
        if (request.TargetAddress is { } address)
        {
            targets = Array.AsReadOnly(targets.Where(t => t.Address.Equals(address)).ToArray());
            if (targets.Count == 0) throw new InvalidOperationException("Выбранный IP отсутствует в списке устройств текущей сети. Обновите устройства.");
        }
        if (request.IncludeLocal && _localPorts is not null && targets.Any(t => t.IsLocal))
        {
            try
            {
                var local = _localPorts.GetListeningPorts(session.Network!).Where(p => p is >= 1 and <= 65535).Distinct().Order().ToArray();
                targets = Array.AsReadOnly(targets.Select(t => t.IsLocal ? t with { ExtraPorts = Array.AsReadOnly(local) } : t).ToArray());
                _localPortNote = local.Length == 0 ? " Дополнительные слушающие TCP-порты этого ПК не обнаружены." :
                    $" Для этого ПК добавлены слушающие TCP-порты из локальной таблицы: {PortScanProfiles.Describe(local)}. Набор портов каждого узла показан в разделе «По узлам».";
            }
            catch (Exception ex) when (ex is System.Net.NetworkInformation.NetworkInformationException or System.Net.Sockets.SocketException or
                PlatformNotSupportedException or UnauthorizedAccessException)
            {
                _logger.Debug("Local TCP listeners unavailable: {ErrorType}", ex.GetType().Name);
                _localPortNote = " Локальная таблица TCP недоступна; этот ПК проверяется только по выбранному профилю портов.";
            }
        }
        return targets;
    }
    private void SetTargets(IReadOnlyList<AuditTarget> targets, IReadOnlyList<int> ports)
    {
        _hosts.Clear();
        foreach (var target in targets)
            _hosts.Add(target.Address, new(target, target.ExtraPorts.Count == 0 ? ports :
                Array.AsReadOnly(ports.Concat(target.ExtraPorts).Distinct().Order().ToArray())));
        _hostsCompleted = 0; _hostsTotal = targets.Count; _total = _hosts.Values.Sum(h => (long)h.Ports.Count);
        _current = _current with { CheckedPorts = Array.AsReadOnly(ports.Concat(targets.SelectMany(t => t.ExtraPorts)).Distinct().Order().ToArray()) };
    }
    private sealed class HostWork(AuditTarget target, IReadOnlyList<int> ports)
    {
        public AuditTarget Target { get; } = target;
        public IReadOnlyList<int> Ports { get; } = ports;
        public bool Started { get; set; }
        public int Checked { get; set; }
        public HashSet<int> InconclusivePorts { get; } = [];
        public bool Inconclusive => InconclusivePorts.Count > 0;
        public DateTimeOffset? LastChecked { get; set; }
        public TargetHostSummary? Summary { get; set; }
        public AuditStage SummaryStage { get; set; }
    }

    private async Task WatchNetworkAsync(NetworkSession session, CancellationToken token)
    {
        try
        {
            while (true)
            {
                await Task.Delay(1000, token).ConfigureAwait(false);
                if (!Matches(session, _sessions.Current) || !await _networks.IsCurrentAsync(session.Network!, token).ConfigureAwait(false))
                { MarkNetworkChanged(); return; }
                Publish();
            }
        }
        catch (OperationCanceledException) { }
        catch (Exception ex) { _logger.Debug("Audit context check: {ErrorType}", ex.GetType().Name); MarkNetworkChanged(); }
    }
    private static bool Matches(NetworkSession expected, NetworkSession current) => current.IsReadyForAudit &&
        expected.SessionId == current.SessionId && current.Network?.HasSameContext(expected.Network!) == true;
    private void CheckSession(NetworkSession expected)
    { if (!Matches(expected, _sessions.Current)) { MarkNetworkChanged(); throw new OperationCanceledException(); } }
    private void SessionChanged(object? sender, NetworkSession session)
    {
        bool changed;
        lock (_gate) changed = _current.SessionId != Guid.Empty &&
            (!session.IsReadyForAudit || session.SessionId != _current.SessionId || _network?.HasSameContext(session.Network!) != true);
        if (changed) MarkNetworkChanged();
    }
    private void MarkNetworkChanged()
    {
        AuditSnapshot snapshot;
        lock (_gate)
        {
            _stopStage = AuditStage.NetworkChanged; _rows.Clear(); _hosts.Clear();
            _current = _current with { Stage = AuditStage.NetworkChanged };
            _cancellation?.Cancel();
            snapshot = SnapshotLocked("Аудит остановлен: сеть изменилась. Обновите устройства новой сессии.");
        }
        Notify(snapshot);
    }
    private string StageMessage() => _current.Stage switch
    {
        AuditStage.Scanning => "Проверка TCP-портов и определение служб.",
        AuditStage.Detecting => "Определение служб на найденных открытых портах.",
        AuditStage.FindingSites => "Поиск HTTP-сайтов и доступных HTML-страниц.",
        AuditStage.Completed => _open == 0 ? "Аудит завершён: открытых TCP-портов не найдено." : "Аудит завершён.",
        AuditStage.NetworkChanged => "Аудит остановлен: сеть изменилась. Обновите устройства новой сессии.",
        AuditStage.Cancelled => "Аудит остановлен пользователем. Частичные результаты сохранены.",
        AuditStage.Failed => _current.Message,
        _ => _current.Message
    };
    private AuditSnapshot SnapshotLocked(string message)
    {
        _lastPublishMs = _watch.ElapsedMilliseconds;
        var rows = _rows.Values.ToArray();
        var byAddress = rows.ToLookup(r => r.Target.Address);
        var summaries = _hosts.Values.Select(host =>
        {
            if (host.Summary is null || host.SummaryStage != _current.Stage)
            {
                host.Summary = TargetServiceMatcher.Summarize(_current.SessionId, _current.AuditId, host.Target,
                    byAddress[host.Target.Address], host.Checked, host.Ports.Count, host.Started, host.Inconclusive,
                    _current.Stage, host.LastChecked) with { TargetPorts = host.Ports };
                host.SummaryStage = _current.Stage;
            }
            return host.Summary;
        }).OrderBy(h => Convert.ToHexString(h.Target.Address.GetAddressBytes()), StringComparer.Ordinal).ToArray();
        return _current = _current with { Version = ++_version, Rows = Array.AsReadOnly(rows), Hosts = Array.AsReadOnly(summaries), Message = message,
            Progress = new(_hostsCompleted, _hostsTotal, _checked, _total, _open, _closed, _timedOut, _unavailable, _errors, _identified, _watch.Elapsed) };
    }
    private void Publish(bool force = false)
    {
        AuditSnapshot snapshot;
        lock (_gate)
        {
            if (_stopStage == AuditStage.NetworkChanged || (!force && _watch.ElapsedMilliseconds - _lastPublishMs < 150)) return;
            snapshot = SnapshotLocked(StageMessage());
        }
        Notify(snapshot);
    }
    private void Notify(AuditSnapshot snapshot)
    {
        foreach (EventHandler<AuditSnapshot> handler in Updated?.GetInvocationList() ?? [])
            try { handler(this, snapshot); } catch (Exception ex) { _logger.Debug("Audit subscriber failed: {ErrorType}", ex.GetType().Name); }
    }
    public Task StopAsync()
    { lock (_gate) { _cancellation?.Cancel(); return _run; } }
    public void Dispose()
    {
        lock (_gate) { if (_disposed) return; _disposed = true; _cancellation?.Cancel(); }
        _sessions.Updated -= SessionChanged;
    }
}
