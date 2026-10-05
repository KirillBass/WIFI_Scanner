using System.Text;
using WirelessSecurityAnalyzer.Core.Analysis;
using WirelessSecurityAnalyzer.Core.Common;
using WirelessSecurityAnalyzer.Core.Models;

namespace WirelessSecurityAnalyzer.Infrastructure.Windows.NativeWifi;

internal static class BssMapper
{
    internal static WifiAccessPoint Map(WlanBssEntry entry, DateTimeOffset observedAt)
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
        return new WifiAccessPoint(ssid, string.Join(":", entry.Bssid.Select(b => b.ToString("X2"))),
            entry.Rssi, Math.Min(entry.LinkQuality, 100), frequency, channel, band, lastSeen, hidden);
    }
}
