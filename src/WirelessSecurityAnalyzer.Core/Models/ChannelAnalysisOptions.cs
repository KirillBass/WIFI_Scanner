namespace WirelessSecurityAnalyzer.Core.Models;

/// <summary>Fixed calibration, independent of the busiest channel in a scan.</summary>
public sealed record ChannelAnalysisOptions
{
    public double RssiFloorDbm { get; init; } = -95;
    public double RssiCeilingDbm { get; init; } = -35;
    public double DefaultChannelWidthMhz { get; init; } = 20;
    public double SaturationRawScore { get; init; } = 3;
    public double FreeThresholdPercent { get; init; } = 20;
    public double LowThresholdPercent { get; init; } = 40;
    public double MediumThresholdPercent { get; init; } = 60;
    public double HighThresholdPercent { get; init; } = 80;
    public string? ExcludedBssid { get; init; }

    /// <summary>Optional override for the analyzed band; null uses the candidate provider.</summary>
    public IReadOnlyList<int>? CandidateChannels { get; init; }

    internal void Validate()
    {
        if (!double.IsFinite(RssiFloorDbm) || !double.IsFinite(RssiCeilingDbm) ||
            !double.IsFinite(RssiCeilingDbm - RssiFloorDbm) || RssiFloorDbm >= RssiCeilingDbm)
            throw new ArgumentException("RSSI floor must be finite and below the ceiling.");
        if (!double.IsFinite(DefaultChannelWidthMhz) || DefaultChannelWidthMhz <= 0)
            throw new ArgumentException("Estimated channel width must be finite and positive.");
        if (!double.IsFinite(SaturationRawScore) || SaturationRawScore <= 0)
            throw new ArgumentException("Saturation score must be finite and positive.");
        var thresholds = new[] { FreeThresholdPercent, LowThresholdPercent, MediumThresholdPercent, HighThresholdPercent };
        if (thresholds.Any(t => !double.IsFinite(t) || t <= 0 || t >= 100) ||
            thresholds.Zip(thresholds.Skip(1)).Any(pair => pair.First >= pair.Second))
            throw new ArgumentException("Load thresholds must increase strictly between 0 and 100.");
    }
}
