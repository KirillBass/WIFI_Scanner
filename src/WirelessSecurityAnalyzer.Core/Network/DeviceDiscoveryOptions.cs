namespace WirelessSecurityAnalyzer.Core.Network;

public sealed record DeviceDiscoveryOptions
{
    public int PingTimeoutMs { get; init; } = 500;
    public int MaxConcurrency { get; init; } = 32;
    public int MaxAutoHostCount { get; init; } = 1024;
    public bool ResolveHostnames { get; init; } = true;
    public int HostnameTimeoutMs { get; init; } = 1000;
    public int HostnameConcurrency { get; init; } = 4;
    public int OfflineAfterMissedScans { get; init; } = 3;

    public void Validate()
    {
        if (PingTimeoutMs is < 100 or > 5000) throw new ArgumentOutOfRangeException(nameof(PingTimeoutMs));
        if (MaxConcurrency is < 1 or > 64) throw new ArgumentOutOfRangeException(nameof(MaxConcurrency));
        if (MaxAutoHostCount is < 1 or > 1024) throw new ArgumentOutOfRangeException(nameof(MaxAutoHostCount));
        if (HostnameTimeoutMs is < 100 or > 5000) throw new ArgumentOutOfRangeException(nameof(HostnameTimeoutMs));
        if (HostnameConcurrency is < 1 or > 8) throw new ArgumentOutOfRangeException(nameof(HostnameConcurrency));
        if (OfflineAfterMissedScans is < 1 or > 100) throw new ArgumentOutOfRangeException(nameof(OfflineAfterMissedScans));
    }
}
