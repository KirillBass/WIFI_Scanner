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
    public IReadOnlyList<byte>? SsidBytes { get; init; }
    /// <summary>Measurement time reported by the source, when available; distinguishes cached BSS data.</summary>
    public DateTimeOffset? MeasurementTimestamp { get; init; }
}
