using WirelessSecurityAnalyzer.Core.Models;

namespace WirelessSecurityAnalyzer.Core.Analysis.Wifi;

public static class WifiStandardDetector
{
    public static WifiStandard Detect(WifiStandard nativeStandard, WifiCapabilities capabilities)
    {
        var ieStandard = capabilities switch
        {
            { HasEht: true } => WifiStandard.Ieee80211be,
            { HasHe: true } => WifiStandard.Ieee80211ax,
            { HasVht: true } => WifiStandard.Ieee80211ac,
            { HasHt: true } => WifiStandard.Ieee80211n,
            _ => WifiStandard.Unknown
        };
        return Rank(ieStandard) > Rank(nativeStandard) ? ieStandard : nativeStandard;
    }

    private static int Rank(WifiStandard standard) => standard switch
    {
        WifiStandard.Ieee80211be => 5, WifiStandard.Ieee80211ax => 4,
        WifiStandard.Ieee80211ac => 3, WifiStandard.Ieee80211n => 2,
        WifiStandard.Ieee80211a or WifiStandard.Ieee80211b or WifiStandard.Ieee80211g => 1, _ => 0
    };
}
