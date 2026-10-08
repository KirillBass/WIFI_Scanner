using WirelessSecurityAnalyzer.Core.Models;

namespace WirelessSecurityAnalyzer.Infrastructure.Windows.NativeWifi;

internal static class WepFallbackResolver
{
    internal static WifiSecurityInfo? Find(WlanBssEntry bss, IReadOnlyList<WlanAvailableNetwork> networks)
    {
        // AvailableNetwork has no BSSID. Only an unambiguous nonhidden one-BSSID network can
        // corroborate WEP; do not transfer another AP's security just because its SSID matches.
        if ((bss.CapabilityInformation & 0x10) == 0 || bss.Ssid.Length is 0 or > 32 ||
            bss.Ssid.Bytes.AsSpan(0, (int)bss.Ssid.Length).IndexOfAnyExcept((byte)0) < 0) return null;
        WifiSecurityInfo? result = null;
        foreach (var network in networks)
        {
            if (network.BssType != bss.BssType || network.Ssid.Length != bss.Ssid.Length ||
                !network.Ssid.Bytes.AsSpan(0, (int)network.Ssid.Length)
                    .SequenceEqual(bss.Ssid.Bytes.AsSpan(0, (int)bss.Ssid.Length))) continue;
            if (network.SecurityEnabled == 0 || network.NumberOfBssids != 1 ||
                network.DefaultAuthAlgorithm is not (Dot11AuthAlgorithm.Open or Dot11AuthAlgorithm.Shared) ||
                network.DefaultCipherAlgorithm is not (Dot11CipherAlgorithm.Wep40 or Dot11CipherAlgorithm.Wep104 or Dot11CipherAlgorithm.Wep))
                return null;
            var cipher = network.DefaultCipherAlgorithm switch
            {
                Dot11CipherAlgorithm.Wep40 => WifiCipherType.Wep40,
                Dot11CipherAlgorithm.Wep104 => WifiCipherType.Wep104, _ => WifiCipherType.Unknown
            };
            var auth = network.DefaultAuthAlgorithm == Dot11AuthAlgorithm.Open
                ? WifiAuthenticationType.Open : WifiAuthenticationType.Shared;
            if (result is not null && (result.Authentication != auth || result.PairwiseCipher != cipher)) return null;
            result = new()
            {
                Protocol = WifiSecurityProtocol.Wep, Authentication = auth, Source = WifiSecuritySource.WindowsNetworkList,
                PairwiseCiphers = Array.AsReadOnly(new[] { cipher }), GroupCipher = cipher
            };
        }
        return result;
    }
}
