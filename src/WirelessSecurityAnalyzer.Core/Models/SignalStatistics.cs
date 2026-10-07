namespace WirelessSecurityAnalyzer.Core.Models;

public sealed record SignalStatistics(int? CurrentRssiDbm, double? AverageRssiDbm,
    int? MinimumRssiDbm, int? MaximumRssiDbm, int SampleCount, DateTimeOffset? LastSeen)
{
    public static SignalStatistics Empty { get; } = new(null, null, null, null, 0, null);
}
