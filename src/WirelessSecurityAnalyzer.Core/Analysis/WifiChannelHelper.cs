using WirelessSecurityAnalyzer.Core.Models;

namespace WirelessSecurityAnalyzer.Core.Analysis;

/// <summary>Converts channel center frequencies; this is not a regulatory availability list.</summary>
public static class WifiChannelHelper
{
    public static (WifiBand Band, int Channel) FromFrequency(double frequencyMhz)
    {
        if (!double.IsFinite(frequencyMhz) || Math.Abs(frequencyMhz - Math.Round(frequencyMhz)) > 0.001)
            return (WifiBand.Unknown, 0);

        if (frequencyMhz == 2484) return (WifiBand.Ghz2_4, 14);
        if (frequencyMhz == 5935) return (WifiBand.Ghz6, 2);
        if (frequencyMhz is >= 2412 and <= 2472 && (frequencyMhz - 2407) % 5 == 0)
            return (WifiBand.Ghz2_4, (int)(frequencyMhz - 2407) / 5);
        if (frequencyMhz is >= 4910 and <= 4980 && (frequencyMhz - 4000) % 5 == 0)
            return (WifiBand.Ghz5, (int)(frequencyMhz - 4000) / 5);
        if (frequencyMhz is >= 5005 and <= 5895 && (frequencyMhz - 5000) % 5 == 0)
            return (WifiBand.Ghz5, (int)(frequencyMhz - 5000) / 5);
        if (frequencyMhz is >= 5955 and <= 7115 && (frequencyMhz - 5950) % 10 == 5)
            return (WifiBand.Ghz6, (int)(frequencyMhz - 5950) / 5);
        return (WifiBand.Unknown, 0);
    }

    public static double? ToFrequency(WifiBand band, int channel) => (band, channel) switch
    {
        (WifiBand.Ghz2_4, 14) => 2484,
        (WifiBand.Ghz2_4, >= 1 and <= 13) => 2407 + channel * 5,
        (WifiBand.Ghz5, >= 182 and <= 196) => 4000 + channel * 5,
        (WifiBand.Ghz5, >= 1 and <= 179) => 5000 + channel * 5,
        (WifiBand.Ghz6, 2) => 5935,
        (WifiBand.Ghz6, >= 1 and <= 233) when channel % 2 == 1 => 5950 + channel * 5,
        _ => null
    };
}
