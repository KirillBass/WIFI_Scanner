using WirelessSecurityAnalyzer.Core.Interfaces;
using WirelessSecurityAnalyzer.Core.Models;

namespace WirelessSecurityAnalyzer.Core.Analysis.Channels;

public sealed class ChannelAnalyzer(IChannelOverlapModel overlapModel, IChannelCandidateProvider candidates,
    TimeProvider? timeProvider = null) : IChannelAnalyzer
{
    private readonly TimeProvider _clock = timeProvider ?? TimeProvider.System;

    public ChannelAnalysisSnapshot Analyze(IReadOnlyList<WifiAccessPoint> accessPoints, WifiBand band,
        ChannelAnalysisOptions? options = null)
    {
        ArgumentNullException.ThrowIfNull(accessPoints);
        options ??= new();
        options.Validate();
        var normalized = new Dictionary<string, WifiAccessPoint>(StringComparer.OrdinalIgnoreCase);
        int ignored = 0, duplicates = 0;
        foreach (var ap in accessPoints)
        {
            if (ap is null || string.IsNullOrWhiteSpace(ap.Bssid)) { ignored++; continue; }
            var (actualBand, channel) = WifiChannelCatalog.FromFrequency(ap.FrequencyMhz);
            if (actualBand == WifiBand.Unknown || channel == 0) { ignored++; continue; }
            var valid = ap with { Bssid = ap.Bssid.Trim().ToUpperInvariant(), Band = actualBand, Channel = channel };
            if (normalized.TryGetValue(valid.Bssid, out var previous))
            {
                duplicates++;
                // Match the scanner's strongest-BSS policy; resolve equal RSSI deterministically.
                if (valid.RssiDbm < previous.RssiDbm || valid.RssiDbm == previous.RssiDbm &&
                    (valid.LastSeen < previous.LastSeen || valid.LastSeen == previous.LastSeen &&
                    (valid.FrequencyMhz > previous.FrequencyMhz || valid.FrequencyMhz == previous.FrequencyMhz &&
                    string.CompareOrdinal(valid.Ssid, previous.Ssid) >= 0))) continue;
            }
            normalized[valid.Bssid] = valid;
        }
        var points = normalized.Values.Where(ap => ap.Band == band &&
            !string.Equals(ap.Bssid, options.ExcludedBssid?.Trim(), StringComparison.OrdinalIgnoreCase))
            .OrderBy(ap => ap.Bssid, StringComparer.Ordinal).ToArray();
        var requested = (options.CandidateChannels ?? candidates.GetChannels(band, points)).Distinct().Order().ToArray();
        var validCandidates = requested.Select(channel => (Channel: channel,
            Frequency: WifiChannelCatalog.GetCenterFrequencyMhz(band, channel))).Where(c => c.Frequency.HasValue).ToArray();
        var weights = points.Select(ap => SignalWeightCalculator.Calculate(ap.RssiDbm, options)).ToArray();
        var results = validCandidates.Select(candidate =>
        {
            double raw = 0;
            int influencing = 0;
            for (var i = 0; i < points.Length; i++)
            {
                var overlap = overlapModel.Calculate(points[i].FrequencyMhz, candidate.Frequency!.Value, options.DefaultChannelWidthMhz);
                if (overlap > 0) influencing++;
                raw += weights[i] * overlap;
            }
            var percent = Math.Clamp(raw / options.SaturationRawScore * 100, 0, 100);
            var level = percent < options.FreeThresholdPercent ? ChannelLoadLevel.Free :
                percent < options.LowThresholdPercent ? ChannelLoadLevel.Low :
                percent < options.MediumThresholdPercent ? ChannelLoadLevel.Medium :
                percent < options.HighThresholdPercent ? ChannelLoadLevel.High : ChannelLoadLevel.Critical;
            return new ChannelAnalysisResult(band, candidate.Channel, candidate.Frequency!.Value,
                points.Count(ap => ap.Channel == candidate.Channel), influencing, raw, percent, level, false, true);
        }).ToArray();
        int? recommended = points.Length == 0 ? null : results.OrderBy(r => r.LoadScorePercent)
            .ThenBy(r => r.InfluencingBssCount).ThenBy(r => r.DirectBssCount).ThenBy(r => r.Channel).FirstOrDefault()?.Channel;
        var channels = Array.AsReadOnly(results.Select(r => r with { IsRecommended = r.Channel == recommended }).ToArray());
        var baseline = points.Length == 0 ? -100 : Math.Min(-100, points.Min(ap => (double)ap.RssiDbm) - 5);
        var spectrum = Array.AsReadOnly(points.Select(ap => CreateCurve(ap, options.DefaultChannelWidthMhz, baseline)).ToArray());
        var description = FormattableString.Invariant($"Estimated {options.DefaultChannelWidthMhz} MHz width; RSSI {options.RssiFloorDbm}..{options.RssiCeilingDbm} dBm; saturation {options.SaturationRawScore}; regional availability unverified.");
        return new(band, channels, recommended, _clock.GetUtcNow(), description, true, spectrum,
            ignored, duplicates, requested.Length - validCandidates.Length);
    }

    private static ChannelSpectrumCurve CreateCurve(WifiAccessPoint ap, double width, double baseline)
    {
        const int segments = 48;
        var xs = new double[segments + 1];
        var ys = new double[segments + 1];
        for (var i = 0; i <= segments; i++)
        {
            var offset = 2.0 * i / segments - 1;
            xs[i] = ap.FrequencyMhz + offset * width / 2;
            ys[i] = baseline + (ap.RssiDbm - baseline) * (1 + Math.Cos(Math.PI * offset)) / 2;
        }
        return new(ap, width, true, Array.AsReadOnly(xs), Array.AsReadOnly(ys));
    }
}
