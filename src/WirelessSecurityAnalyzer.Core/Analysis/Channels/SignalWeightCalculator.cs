using WirelessSecurityAnalyzer.Core.Models;

namespace WirelessSecurityAnalyzer.Core.Analysis.Channels;

public static class SignalWeightCalculator
{
    public static double Calculate(int rssiDbm, ChannelAnalysisOptions? options = null)
    {
        options ??= new();
        options.Validate();
        return Math.Clamp((rssiDbm - options.RssiFloorDbm) /
            (options.RssiCeilingDbm - options.RssiFloorDbm), 0, 1);
    }
}
