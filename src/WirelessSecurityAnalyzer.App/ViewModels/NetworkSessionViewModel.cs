using Avalonia.Threading;
using WirelessSecurityAnalyzer.Core.Interfaces;
using WirelessSecurityAnalyzer.Core.Models;

namespace WirelessSecurityAnalyzer.App.ViewModels;

/// <summary>One UI-thread projection of the shared application session.</summary>
public sealed class NetworkSessionViewModel : ViewModelBase, IDisposable
{
    private readonly INetworkSessionService _sessions;
    public NetworkSessionViewModel(INetworkSessionService sessions)
    {
        _sessions = sessions;
        Current = sessions.Current;
        sessions.Updated += OnUpdated;
    }
    public NetworkSession Current { get; private set; }
    public bool IsConnected => Current.IsConnected;
    public bool IsReady => Current.IsReadyForAudit;
    public bool IsObtainingAddress => Current.State is WifiConnectionState.Connected or WifiConnectionState.ObtainingAddress;
    public bool CanDisconnectWifi => IsConnected && !Current.IsInterfaceSelection && Current.Network?.IsWireless != false;
    public void SelectNetwork(LocalNetworkInfo network) => _sessions.SelectNetwork(network);
    public bool IsConnecting => Current.State is WifiConnectionState.Connecting or WifiConnectionState.Authenticating or WifiConnectionState.Disconnecting;
    public string Ssid => Clean(Current.Ssid);
    public string Bssid => Current.Bssid ?? "-";
    public string InterfaceName => Clean(Current.InterfaceName);
    public string Ipv4 => Current.Ipv4 ?? "-";
    public string Subnet => Current.Subnet ?? "-";
    public string Gateway => Current.Gateway ?? "-";
    public string Security => WifiDisplayFormatter.Security(Current.Security);
    public string ConnectedAt => Current.ConnectedAt?.ToLocalTime().ToString("dd.MM.yyyy HH:mm:ss") ?? "-";
    public string Status => Current.State switch
    {
        WifiConnectionState.Connecting => "Подключение к Wi-Fi…",
        WifiConnectionState.Authenticating => "Подключение: проверка аутентификации…",
        WifiConnectionState.Connected or WifiConnectionState.ObtainingAddress => "Подключено к Wi-Fi, получение IP…",
        WifiConnectionState.Ready => "Выбранная IPv4-сеть готова к поиску устройств и аудиту.",
        WifiConnectionState.Disconnecting => "Отключение от Wi-Fi…",
        WifiConnectionState.Failed => "Подключение не установлено.",
        _ => "Выберите сетевой интерфейс или подключитесь к Wi-Fi."
    };
    public string Summary => IsReady ? $"{InterfaceName} · {Ipv4}/{Current.PrefixLength}" +
        (Current.Ssid is { Length: > 0 } ? $" · {Ssid}" : "") : Status;

    public void Refresh() => OnUpdated(_sessions, _sessions.Current);

    private void OnUpdated(object? sender, NetworkSession session)
    {
        void Apply()
        {
            if (session.Version <= Current.Version) return;
            Current = session;
            OnPropertyChanged(nameof(Current));
            OnPropertyChanged(string.Empty);
        }
        if (Dispatcher.UIThread.CheckAccess()) Apply();
        else Dispatcher.UIThread.Post(Apply);
    }
    private static string Clean(string? text) => string.IsNullOrEmpty(text) ? "-" : string.Concat(text.Select(c => char.IsControl(c) ? '□' : c));
    public void Dispose() => _sessions.Updated -= OnUpdated;
}
