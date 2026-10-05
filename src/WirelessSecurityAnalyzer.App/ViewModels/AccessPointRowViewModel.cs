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
