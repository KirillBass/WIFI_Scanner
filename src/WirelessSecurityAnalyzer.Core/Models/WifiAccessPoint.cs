namespace WirelessSecurityAnalyzer.Core.Models;

public sealed record WifiAccessPoint(
    string Ssid,
    string Bssid,
    int RssiDbm,
    uint LinkQuality,
    double FrequencyMhz,
    int Channel,
    WifiBand Band,
    DateTimeOffset LastSeen,
    bool IsHidden)
{
    public string? Vendor { get; init; }
    public bool IsVendorLocallyAdministered { get; init; }
    public WifiStandard Standard { get; init; }
    public WifiSecurityInfo Security { get; init; } = WifiSecurityInfo.Unknown;
    public bool IsSecurityEnabled { get; init; }
}
