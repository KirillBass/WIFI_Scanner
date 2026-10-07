using WirelessSecurityAnalyzer.Core.Common;

namespace WirelessSecurityAnalyzer.Core.Models;

public sealed record WifiMonitorSnapshot(long Version, string? Bssid, bool IsMonitoring,
    TimeSpan Interval, bool? IsPresentInLastScan, IReadOnlyList<SignalSample> Samples,
    SignalStatistics Statistics, WifiException? Error);
