using System.Globalization;
using WirelessSecurityAnalyzer.Core.Models;

namespace WirelessSecurityAnalyzer.App.ViewModels;

public sealed class AccessPointRowViewModel(WifiAccessPoint accessPoint) : ViewModelBase
{
    private WifiAccessPoint _accessPoint = accessPoint;
    public WifiAccessPoint AccessPoint => _accessPoint;
    public string Ssid => _accessPoint.IsHidden ? "〈Скрытая сеть〉" :
        string.Concat(_accessPoint.Ssid.Select(c => char.IsControl(c) ? '□' : c));
    public string Bssid => _accessPoint.Bssid;
    public string Vendor => _accessPoint.IsVendorLocallyAdministered ? "Локальный / приватный MAC" :
        string.IsNullOrWhiteSpace(_accessPoint.Vendor) ? "Не определено" : _accessPoint.Vendor;
    public string WifiStandard => WifiDisplayFormatter.Standard(_accessPoint.Standard, _accessPoint.Band);
    public string Security => WifiDisplayFormatter.Security(_accessPoint.Security);
    public string SecurityDetails => $"Протокол: {WifiDisplayFormatter.Protocol(_accessPoint.Security.Protocol)}\n" +
        $"Аутентификация: {WifiDisplayFormatter.Authentication(_accessPoint.Security.Authentication)}\n" +
        $"Pairwise: {WifiDisplayFormatter.PairwiseCiphers(_accessPoint.Security)}\n" +
        $"Group: {WifiDisplayFormatter.Cipher(_accessPoint.Security.GroupCipher)}\n" +
        $"PMF: {WifiDisplayFormatter.ManagementFrameProtection(_accessPoint.Security)}\n" +
        $"Источник: {WifiDisplayFormatter.Source(_accessPoint.Security.Source)}";
    public string Details => $"SSID: {Ssid} · BSSID: {Bssid} · Вендор: {Vendor}\n" +
        $"RSSI: {RssiDbm} dBm · Link Quality: {LinkQuality}% · Канал: {Channel} · {Band} · {Frequency}\n" +
        $"Стандарт: {WifiStandard} · Безопасность: {Security} · Аутентификация: {WifiDisplayFormatter.Authentication(_accessPoint.Security.Authentication)}\n" +
        $"Pairwise: {WifiDisplayFormatter.PairwiseCiphers(_accessPoint.Security)} · Group: {WifiDisplayFormatter.Cipher(_accessPoint.Security.GroupCipher)} · PMF: {WifiDisplayFormatter.ManagementFrameProtection(_accessPoint.Security)}\n" +
        $"Источник защиты: {WifiDisplayFormatter.Source(_accessPoint.Security.Source)} · Обнаружена: {LastSeen}";
    public string DisplayName => $"{Ssid} | {Bssid} | канал {Channel} | {RssiDbm} dBm";
    public int RssiDbm => _accessPoint.RssiDbm;
    public uint LinkQuality => _accessPoint.LinkQuality;
    public string Channel => _accessPoint.Channel > 0 ? _accessPoint.Channel.ToString(CultureInfo.InvariantCulture) : "—";
    public string Band => FormatBand(_accessPoint.Band);
    public string Frequency => _accessPoint.FrequencyMhz.ToString("0.###", CultureInfo.GetCultureInfo("ru-RU")) + " МГц";
    public string LastSeen => _accessPoint.LastSeen.ToLocalTime().ToString("dd.MM HH:mm:ss", CultureInfo.GetCultureInfo("ru-RU"));

    public void Update(WifiAccessPoint accessPoint)
    {
        if (_accessPoint == accessPoint) return;
        _accessPoint = accessPoint;
        OnPropertyChanged(string.Empty);
    }

    public static string FormatBand(WifiBand band) => band switch
    {
        WifiBand.Ghz2_4 => "2,4 ГГц", WifiBand.Ghz5 => "5 ГГц", WifiBand.Ghz6 => "6 ГГц", _ => "Неизвестно"
    };
}
