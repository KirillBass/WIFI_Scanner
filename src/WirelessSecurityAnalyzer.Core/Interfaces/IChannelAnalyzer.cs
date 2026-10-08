using WirelessSecurityAnalyzer.Core.Models;

namespace WirelessSecurityAnalyzer.Core.Interfaces;

public interface IChannelAnalyzer
{
    ChannelAnalysisSnapshot Analyze(IReadOnlyList<WifiAccessPoint> accessPoints, WifiBand band,
        ChannelAnalysisOptions? options = null);
}
