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
    bool IsHidden);
