using WirelessSecurityAnalyzer.Core.Models;

namespace WirelessSecurityAnalyzer.Core.Interfaces;

/// <summary>Candidate policy; it does not certify regulatory or adapter availability.</summary>
public interface IChannelCandidateProvider
{
    IReadOnlyList<int> GetChannels(WifiBand band, IReadOnlyList<WifiAccessPoint> accessPoints);
}
