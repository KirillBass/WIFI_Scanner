using WirelessSecurityAnalyzer.Core.Interfaces;
using WirelessSecurityAnalyzer.Core.Models;

namespace WirelessSecurityAnalyzer.Core.Analysis.Channels;

/// <summary>
/// Common 20 MHz candidates, not a regulatory list. A region/adapter provider can
/// replace this service or supply an explicit per-band configuration.
/// </summary>
public sealed class WifiChannelCatalog : IChannelCandidateProvider
{
    private readonly IReadOnlyDictionary<WifiBand, IReadOnlyList<int>>? _configured;

    public WifiChannelCatalog(IReadOnlyDictionary<WifiBand, IReadOnlyList<int>>? configuredChannels = null)
    {
        _configured = configuredChannels?.ToDictionary(pair => pair.Key,
            pair => (IReadOnlyList<int>)Array.AsReadOnly(pair.Value.ToArray()));
    }

    public IReadOnlyList<int> GetChannels(WifiBand band, IReadOnlyList<WifiAccessPoint> accessPoints)
    {
        if (_configured is not null) return _configured.GetValueOrDefault(band) ?? Array.Empty<int>();
        IEnumerable<int> channels = band switch
        {
            WifiBand.Ghz2_4 => Enumerable.Range(1, 13),
            WifiBand.Ghz5 => new[] { 36, 40, 44, 48, 52, 56, 60, 64, 100, 104, 108, 112,
                116, 120, 124, 128, 132, 136, 140, 144, 149, 153, 157, 161, 165 },
            WifiBand.Ghz6 => Enumerable.Range(0, 59).Select(index => 1 + index * 4),
            _ => []
        };
        // Special channels are never added speculatively. A configured provider may allow them explicitly.
        if (band == WifiBand.Ghz2_4 && accessPoints.Any(ap => ap.Band == band && ap.Channel == 14))
            channels = channels.Append(14);
        if (band == WifiBand.Ghz6 && accessPoints.Any(ap => ap.Band == band && ap.Channel == 2))
            channels = channels.Append(2);
        return Array.AsReadOnly(channels.Order().ToArray());
    }

    public static double? GetCenterFrequencyMhz(WifiBand band, int channel) => WifiChannelHelper.ToFrequency(band, channel);
    public static (WifiBand Band, int Channel) FromFrequency(double frequencyMhz) => WifiChannelHelper.FromFrequency(frequencyMhz);
}
