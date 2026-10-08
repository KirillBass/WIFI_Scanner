using System.Text;
using WirelessSecurityAnalyzer.Core.Analysis;
using WirelessSecurityAnalyzer.Core.Analysis.Wifi;
using WirelessSecurityAnalyzer.Core.Common;
using WirelessSecurityAnalyzer.Core.Models;

namespace WirelessSecurityAnalyzer.Infrastructure.Windows.NativeWifi;

internal static class BssMapper
{
    internal static WifiAccessPoint Map(WlanBssEntry entry, DateTimeOffset observedAt,
        WifiCapabilities? capabilities = null, DeviceIdentity? vendor = null,
        WifiSecurityInfo? windowsWep = null, bool informationElementsAvailable = true)
    {
        if (entry.Ssid.Length > 32 || entry.Bssid.Length != 6)
            throw new WifiException(WifiErrorKind.InvalidNativeData, "Invalid BSS record.");

        var bytes = entry.Ssid.Bytes.AsSpan(0, (int)entry.Ssid.Length);
        var hidden = bytes.Length == 0 || bytes.IndexOfAnyExcept((byte)0) < 0;
        // SSIDs are byte strings. Replacement characters keep invalid UTF-8 displayable.
        var ssid = hidden ? string.Empty : Encoding.UTF8.GetString(bytes);
        var frequency = entry.CenterFrequencyKhz / 1000d;
        var (band, channel) = WifiChannelHelper.FromFrequency(frequency);
        var lastSeen = observedAt;
        if (entry.HostTimestamp > 0 && entry.HostTimestamp <= (ulong)long.MaxValue)
        {
            try { lastSeen = DateTimeOffset.FromFileTime((long)entry.HostTimestamp); }
            catch (ArgumentOutOfRangeException) { lastSeen = observedAt; }
        }
        capabilities ??= new WifiCapabilities();
        var privacy = (entry.CapabilityInformation & 0x10) != 0;
        return new WifiAccessPoint(ssid, string.Join(":", entry.Bssid.Select(b => b.ToString("X2"))),
            entry.Rssi, Math.Min(entry.LinkQuality, 100), frequency, channel, band, lastSeen, hidden)
        {
            Vendor = vendor?.Vendor, IsVendorLocallyAdministered = vendor?.IsPrivateMac ?? false,
            Standard = WifiStandardDetector.Detect(NativeStandard(entry.PhyType, band), capabilities),
            Security = WifiSecurityDetector.Detect(capabilities, privacy, windowsWep, informationElementsAvailable),
            IsSecurityEnabled = privacy || capabilities.HasRsn || capabilities.HasWpa
        };
    }

    internal static WifiStandard NativeStandard(uint phyType, WifiBand band) => (Dot11PhyType)phyType switch
    {
        Dot11PhyType.Ofdm when band == WifiBand.Ghz5 => WifiStandard.Ieee80211a,
        Dot11PhyType.HrDsss when band == WifiBand.Ghz2_4 => WifiStandard.Ieee80211b,
        Dot11PhyType.Erp when band == WifiBand.Ghz2_4 => WifiStandard.Ieee80211g,
        Dot11PhyType.Ht => WifiStandard.Ieee80211n, Dot11PhyType.Vht => WifiStandard.Ieee80211ac,
        Dot11PhyType.He => WifiStandard.Ieee80211ax, Dot11PhyType.Eht => WifiStandard.Ieee80211be,
        _ => WifiStandard.Unknown
    };
}
