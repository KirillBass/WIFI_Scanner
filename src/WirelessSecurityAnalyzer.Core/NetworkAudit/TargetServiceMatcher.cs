namespace WirelessSecurityAnalyzer.Core.NetworkAudit;

public enum TargetHostState { Pending, Scanning, Matched, NoConfirmedMatch, Partial }

/// <summary>A view of one audit's targets, never a second registry of network devices.</summary>
public sealed record TargetHostSummary(Guid SessionId, Guid AuditId, AuditTarget Target, TargetHostState State,
    IReadOnlyList<AuditRow> Endpoints, int CheckedPortCount, int TotalPortCount, DateTimeOffset? LastCheckedAt, bool IsPartial)
{
    public bool HasMatch => Endpoints.Count > 0;
    public string Address => Target.Address.ToString();
    public string Name => Target.Name;
    public int EndpointCount => Endpoints.Count;
    public string Services => string.Join(", ", Endpoints.Select(e => $"{e.Port}/{TargetServiceMatcher.Family(e.Protocol)}"));
    public string CheckedPortsText => $"{CheckedPortCount}/{TotalPortCount}";
    public string LastCheckedText => LastCheckedAt?.ToLocalTime().ToString("dd.MM HH:mm:ss") ?? "-";
    public string StateText => State switch
    {
        TargetHostState.Pending => "Ожидает проверки", TargetHostState.Scanning => "Проверяется",
        TargetHostState.Matched => IsPartial ? "Подтверждено, результат неполный" : "Целевая служба подтверждена",
        TargetHostState.Partial => "Проверка неполная", _ => "Нет подтверждённых совпадений"
    };
}

public static class TargetServiceMatcher
{
    public static string? Family(string protocol) => protocol.ToUpperInvariant() switch
    {
        "SMB" or "SMB2" or "SMB3" => "SMB", "FTP" => "FTP", "HTTP" => "HTTP", "HTTPS" => "HTTPS", _ => null
    };

    // Current detectors reserve High for protocol evidence. Medium FTP greetings are ambiguous with SMTP.
    public static bool IsConfirmed(ServiceIdentity service) => Family(service.Protocol) is not null &&
        service.Confidence == ServiceConfidence.High && !string.IsNullOrWhiteSpace(service.Evidence);

    public static bool Matches(AuditRow row, Guid sessionId, Guid auditId) =>
        sessionId != Guid.Empty && auditId != Guid.Empty && row.SessionId == sessionId && row.AuditId == auditId && IsConfirmed(row.Service);

    public static TargetHostSummary Summarize(Guid sessionId, Guid auditId, AuditTarget target, IEnumerable<AuditRow> rows,
        int checkedPorts, int totalPorts, bool started, bool inconclusive, AuditStage stage, DateTimeOffset? lastCheckedAt)
    {
        var endpoints = rows.Where(r => r.SessionId == sessionId && r.AuditId == auditId && r.Target.Address.Equals(target.Address))
            .GroupBy(r => r.Port).Select(g => g.OrderByDescending(r => r.DetectedAt).First())
            .Where(r => Matches(r, sessionId, auditId)).OrderBy(r => r.Port).ToArray();
        var interrupted = stage is AuditStage.Cancelled or AuditStage.NetworkChanged or AuditStage.Failed;
        var complete = totalPorts > 0 && checkedPorts >= totalPorts;
        var partial = interrupted || inconclusive || !complete;
        var state = endpoints.Length > 0 ? TargetHostState.Matched : interrupted || complete && inconclusive ? TargetHostState.Partial :
            complete ? TargetHostState.NoConfirmedMatch : started ? TargetHostState.Scanning : TargetHostState.Pending;
        return new(sessionId, auditId, target, state, Array.AsReadOnly(endpoints), checkedPorts, totalPorts, lastCheckedAt, partial);
    }
}

public static class TargetServiceProfile
{
    public static IReadOnlyList<int> DefaultPorts { get; } = Array.AsReadOnly(new[] { 21, 80, 443, 445, 8000, 8080, 8443 });
    public static IReadOnlyList<int> GetPorts(string additionalPorts = "") => string.IsNullOrWhiteSpace(additionalPorts)
        ? DefaultPorts : Array.AsReadOnly(DefaultPorts.Concat(PortScanProfiles.Parse(additionalPorts)).Distinct().Order().ToArray());
}
