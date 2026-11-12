using System.Net;
using WirelessSecurityAnalyzer.Core.Models;

namespace WirelessSecurityAnalyzer.Core.NetworkAudit;

public enum PortState { Open, Closed, Timeout, Unavailable, Error }
public enum AuditStage { Idle, Preparing, Scanning, Detecting, Completed, Cancelled, NetworkChanged, Failed, FindingSites }
public enum ServiceConfidence { Unknown, Low, Medium, High }
public enum PortProfile { Quick, Standard, Full, Custom, Targeted }
public sealed record AuditTarget(IPAddress Address, string Name, bool IsLocal, bool IsGateway)
{
    public IReadOnlyList<string> KnownHostnames { get; init; } = [];
    public IReadOnlyList<int> ExtraPorts { get; init; } = [];
    public string DisplayText => $"{Address} · {Name}";
}
public sealed record PortScanResult(IPAddress Address, int Port, PortState State, TimeSpan Elapsed, string? Error = null);
public sealed record ServiceIdentity(string Protocol, string? Product, string? Version,
    ServiceConfidence Confidence, string Evidence, string Metadata = "")
{
    public static ServiceIdentity Unknown { get; } = new("Unknown", null, null, ServiceConfidence.Unknown, "Ответ протокола не получен.");
}
public sealed record AuditRow(Guid SessionId, AuditTarget Target, int Port, ServiceIdentity Service,
    DateTimeOffset DetectedAt, PortProfile Profile)
{
    public Guid AuditId { get; init; }
    public IReadOnlyList<HttpSiteResult> HttpSites { get; init; } = [];
    public string SiteSummary => HttpSites.Count > 0 ? string.Join("; ", HttpSites.Select(s => s.Summary)) : "Проверка не проводилась";
    public string Address => Target.Address.ToString();
    public string Name => Target.Name;
    public string Transport => "TCP";
    public string Protocol => Service.Protocol;
    public string Product => Service.Product ?? "-";
    public string Version => Service.Version ?? "-";
    public string Confidence => Service.Confidence.ToString();
    public string CheckedAtText => DetectedAt.ToLocalTime().ToString("dd.MM HH:mm:ss");
    public string Details => $"{Address}:{Port} · {Name}\nTCP · {Protocol} · {Product} · {Version}\nДостоверность: {Confidence}\nПрофиль: {Profile} · {DetectedAt:dd.MM.yyyy HH:mm:ss}\n{Service.Evidence}\n{Service.Metadata}";
}
public sealed record AuditProgress(int HostsCompleted, int HostsTotal, long Checked, long Total,
    long Open, long Closed, long TimedOut, long Unavailable, long Errors, long Identified, TimeSpan Elapsed);
public sealed record AuditSnapshot(long Version, Guid AuditId, Guid SessionId, AuditStage Stage, bool IsRunning,
    IReadOnlyList<AuditRow> Rows, AuditProgress Progress, string Message)
{
    public IReadOnlyList<TargetHostSummary> Hosts { get; init; } = [];
    public IReadOnlyList<int> CheckedPorts { get; init; } = [];
    public PortProfile Profile { get; init; }
    public bool TargetServicesOnly { get; init; }
    public string ScopeNote { get; init; } = "";
    public static AuditSnapshot Empty { get; } = new(0, Guid.Empty, Guid.Empty, AuditStage.Idle, false, [],
        new(0, 0, 0, 0, 0, 0, 0, 0, 0, 0, TimeSpan.Zero), "Аудит ещё не запускался.");
}
public sealed record AuditRequest(PortProfile Profile = PortProfile.Quick, string CustomPorts = "",
    bool IncludeLocal = true, int Concurrency = 64, int ConnectTimeoutMs = 650)
{
    public bool TargetServicesOnly { get; init; }
    public string AdditionalPorts { get; init; } = "";
    public IPAddress? TargetAddress { get; init; }
}

public interface ILocalTcpPortProvider
{
    IReadOnlyList<int> GetListeningPorts(LocalNetworkInfo network);
}

/// <summary>The stream is owned by this connection; detectors must not retain it.</summary>
public sealed class PortScanConnection(PortScanResult result, Stream? stream = null) : IAsyncDisposable
{
    public PortScanResult Result { get; } = result;
    public Stream? Stream { get; } = stream;
    public ValueTask DisposeAsync() => Stream?.DisposeAsync() ?? ValueTask.CompletedTask;
}
public sealed record ServiceProbe(IPAddress Address, int Port, ReadOnlyMemory<byte> Banner,
    Func<CancellationToken, Task<Stream>> OpenStreamAsync);
public interface IPortScanner
{
    Task<PortScanConnection> ConnectAsync(LocalNetworkInfo network, IPAddress address, int port,
        TimeSpan timeout, CancellationToken cancellationToken);
}
public interface IServiceDetector
{
    string Name { get; }
    bool IsPassive { get; }
    bool IsPreferred(int port);
    Task<ServiceIdentity?> DetectAsync(ServiceProbe probe, CancellationToken cancellationToken);
}
public interface IServiceDetectionEngine
{
    Task<ServiceIdentity> DetectAsync(LocalNetworkInfo network, PortScanConnection connection, CancellationToken cancellationToken);
    Task<ServiceIdentity> DetectTargetedAsync(LocalNetworkInfo network, PortScanConnection connection, CancellationToken cancellationToken) =>
        DetectAsync(network, connection, cancellationToken);
}
public interface INetworkAuditService
{
    AuditSnapshot Current { get; }
    event EventHandler<AuditSnapshot>? Updated;
    Task RunAsync(AuditRequest request, CancellationToken cancellationToken = default);
    Task StopAsync();
}
