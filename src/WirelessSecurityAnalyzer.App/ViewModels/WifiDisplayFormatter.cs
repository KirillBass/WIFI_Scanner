using WirelessSecurityAnalyzer.Core.Models;

namespace WirelessSecurityAnalyzer.App.ViewModels;

public static class WifiDisplayFormatter
{
    public static string Standard(WifiStandard standard, WifiBand band) => standard switch
    {
        WifiStandard.Ieee80211a => "802.11a", WifiStandard.Ieee80211b => "802.11b", WifiStandard.Ieee80211g => "802.11g",
        WifiStandard.Ieee80211n => "802.11n / Wi-Fi 4", WifiStandard.Ieee80211ac => "802.11ac / Wi-Fi 5",
        WifiStandard.Ieee80211ax => band == WifiBand.Ghz6 ? "802.11ax / Wi-Fi 6E" : "802.11ax / Wi-Fi 6",
        WifiStandard.Ieee80211be => "802.11be / Wi-Fi 7", _ => "Не определено"
    };

    public static string Security(WifiSecurityInfo security)
    {
        var protocol = Protocol(security.Protocol);
        return security.Protocol is WifiSecurityProtocol.Wpa or WifiSecurityProtocol.Wpa2 or
            WifiSecurityProtocol.Wpa3 or WifiSecurityProtocol.Wpa2Wpa3Mixed
            ? protocol + (security.Authentication switch
            {
                WifiAuthenticationType.Personal => "-Personal", WifiAuthenticationType.Enterprise => "-Enterprise", _ => ""
            }) : protocol;
    }

    public static string Protocol(WifiSecurityProtocol protocol) => protocol switch
    {
        WifiSecurityProtocol.Open => "Open", WifiSecurityProtocol.Wep => "WEP", WifiSecurityProtocol.Wpa => "WPA",
        WifiSecurityProtocol.Wpa2 => "WPA2", WifiSecurityProtocol.Wpa3 => "WPA3",
        WifiSecurityProtocol.Wpa2Wpa3Mixed => "WPA2/WPA3", WifiSecurityProtocol.Owe => "OWE", _ => "Не определено"
    };

    public static string Authentication(WifiAuthenticationType authentication) => authentication switch
    {
        WifiAuthenticationType.Open => "Open", WifiAuthenticationType.Shared => "Shared",
        WifiAuthenticationType.Personal => "Personal", WifiAuthenticationType.Enterprise => "Enterprise", _ => "Не определено"
    };

    public static string Cipher(WifiCipherType cipher) => cipher switch
    {
        WifiCipherType.None => "Отсутствует", WifiCipherType.Wep40 => "WEP-40", WifiCipherType.Wep104 => "WEP-104",
        WifiCipherType.Tkip => "TKIP", WifiCipherType.Ccmp => "CCMP / AES-128", WifiCipherType.Gcmp => "GCMP / AES-128",
        WifiCipherType.Gcmp256 => "GCMP-256", WifiCipherType.Ccmp256 => "CCMP-256", _ => "Не определено"
    };

    public static string PairwiseCiphers(WifiSecurityInfo security) => security.PairwiseCiphers.Count == 0
        ? "Не определено" : string.Join(", ", security.PairwiseCiphers.Select(Cipher));

    public static string Source(WifiSecuritySource source) => source switch
    {
        WifiSecuritySource.BssCapabilities => "Capability / Privacy bit",
        WifiSecuritySource.WindowsNetworkList => "Native Wi-Fi + Privacy bit",
        WifiSecuritySource.WpaInformationElement => "WPA IE", WifiSecuritySource.RsnInformationElement => "RSN IE",
        _ => "Не определено"
    };

    public static string ManagementFrameProtection(WifiSecurityInfo security) => security switch
    {
        { ManagementFrameProtectionRequired: true } => "Обязательно",
        { ManagementFrameProtectionCapable: true } => "Поддерживается",
        { ManagementFrameProtectionCapable: false } => "Не объявлено", _ => "Не определено"
    };
}
