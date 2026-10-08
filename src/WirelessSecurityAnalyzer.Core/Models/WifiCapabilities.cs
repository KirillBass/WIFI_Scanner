using WirelessSecurityAnalyzer.Core.Analysis.Wifi;

namespace WirelessSecurityAnalyzer.Core.Models;

public sealed record WifiCapabilities
{
    public bool HasHt { get; init; }
    public bool HasVht { get; init; }
    public bool HasHe { get; init; }
    public bool HasEht { get; init; }
    public WifiStandard Standard => WifiStandardDetector.Detect(WifiStandard.Unknown, this);
    public WifiSecurityInfo Security { get; init; } = WifiSecurityInfo.Unknown;
    public bool HasRsn { get; init; }
    public bool HasWpa { get; init; }
    public bool HasMalformedElements { get; init; }
    // A truncated TLV or security element cannot prove the absence of RSN/WPA.
    public bool HasIncompleteSecurityData { get; init; }
}
