namespace WirelessSecurityAnalyzer.Core.Models;

public sealed record WifiScanSnapshot(long Version, DateTimeOffset CompletedAt,
    IReadOnlyList<WifiAccessPoint> AccessPoints);
