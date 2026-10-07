using WirelessSecurityAnalyzer.Core.Models;

namespace WirelessSecurityAnalyzer.Core.Analysis;

public static class SignalStatisticsCalculator
{
    public static SignalStatistics Calculate(IReadOnlyList<SignalSample> samples)
    {
        ArgumentNullException.ThrowIfNull(samples);
        if (samples.Count == 0) return SignalStatistics.Empty;
        var latest = samples.Aggregate((latest, next) => next.Timestamp >= latest.Timestamp ? next : latest);
        return new SignalStatistics(latest.RssiDbm, samples.Average(s => (double)s.RssiDbm),
            samples.Min(s => s.RssiDbm), samples.Max(s => s.RssiDbm), samples.Count, latest.Timestamp);
    }
}
