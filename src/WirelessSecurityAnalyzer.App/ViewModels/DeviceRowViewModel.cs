using System.Globalization;
using CommunityToolkit.Mvvm.ComponentModel;
using WirelessSecurityAnalyzer.Core.Models;

namespace WirelessSecurityAnalyzer.App.ViewModels;

public sealed partial class DeviceRowViewModel(NetworkDevice device) : ObservableObject
{
    private static readonly CultureInfo Russian = CultureInfo.GetCultureInfo("ru-RU");
    [ObservableProperty] private NetworkDevice _device = device;
    public string Ip => Device.IpAddress.ToString();
    public string Mac => Device.MacAddress is null ? "—" : string.Join(":", Device.MacAddress.GetAddressBytes().Select(b => b.ToString("X2")));
    public string Hostname => string.IsNullOrWhiteSpace(Device.Hostname) ? "—" : Device.Hostname;
    public string Latency => Device.Latency is { } value ? $"{value.TotalMilliseconds.ToString("0.#", Russian)} мс" : "—";
    public string State => Device.State.ToString();
    public string StateDescription => Device.State switch
    {
        DeviceState.Online => "В сети: есть ответ ICMP, свежие данные соседей или это локальный компьютер.",
        DeviceState.Offline => "Недоступно: присутствие не подтверждено в нескольких завершённых циклах.",
        _ => "Неизвестно: в текущем цикле присутствие не подтверждено. Возможны сон или фильтрация."
    };
    public string FirstSeen => Device.FirstSeen.ToLocalTime().ToString("dd.MM HH:mm:ss", Russian);
    public string LastSeen => Device.LastSeen.ToLocalTime().ToString("dd.MM HH:mm:ss", Russian);
    public string Role => Device.IsLocalMachine ? "Этот ПК" : Device.IsGateway ? "Шлюз" : "—";
    public bool IsOnline => Device.State == DeviceState.Online;
    public bool IsOffline => Device.State == DeviceState.Offline;
    public bool IsUnknown => Device.State == DeviceState.Unknown;

    partial void OnDeviceChanged(NetworkDevice value)
    {
        foreach (var name in new[] { nameof(Ip), nameof(Mac), nameof(Hostname), nameof(Latency), nameof(State),
            nameof(FirstSeen), nameof(LastSeen), nameof(Role), nameof(StateDescription), nameof(IsOnline), nameof(IsOffline), nameof(IsUnknown) }) OnPropertyChanged(name);
    }
}
