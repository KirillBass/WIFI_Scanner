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
    public string Hostname => Device.Identity?.Hostname ?? (string.IsNullOrWhiteSpace(Device.Hostname) ? "—" : Device.Hostname);
    public string DisplayName => Device.DisplayName == "—" && Device.IsIdentityResolving ? "Определяется…" : Device.DisplayName;
    public string Vendor => Device.Vendor ?? (Device.Identity?.IsPrivateMac == true ? "Приватный / случайный MAC" : "—");
    public string IdentityDetails => $"IP: {Ip}\nMAC: {Mac}\nРоль: {Role}\nСостояние: {State}\nПервый раз: {FirstSeen}\nПоследний раз: {LastSeen}\n" +
        $"Имя: {Device.DisplayName}\nHostname: {Hostname}\nFriendly name: {Device.FriendlyName ?? "—"}\n" +
        $"Производитель: {Vendor}\nИсточник производителя: {Device.Identity?.VendorSource.ToString() ?? "None"}\n" +
        $"Модель: {Device.ModelName ?? "—"}\nОписание: {Device.Identity?.ModelDescription ?? "—"}\nТип: {Device.DeviceType ?? "—"}\n" +
        $"Источник имени: {Device.NameSource}\nИсточник hostname: {Device.Identity?.HostnameSource.ToString() ?? "None"}\n" +
        $"Источник friendly name: {Device.Identity?.FriendlyNameSource.ToString() ?? "None"}\n" +
        $"Источник модели: {Device.Identity?.ModelNameSource.ToString() ?? "None"}\nИсточник типа: {Device.Identity?.DeviceTypeSource.ToString() ?? "None"}\n" +
        $"Достоверность: {Device.Identity?.Confidence.ToString() ?? "Unknown"}\n" +
        $"Приватный MAC: {(Device.Identity?.IsPrivateMac == true ? "Да" : "Нет")}\n" +
        $"Обновлено: {(Device.IdentityLastUpdated is { } updated ? updated.ToLocalTime().ToString("dd.MM HH:mm:ss", Russian) : "—")}";
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
        foreach (var name in new[] { nameof(Ip), nameof(Mac), nameof(Hostname), nameof(DisplayName), nameof(Vendor), nameof(IdentityDetails), nameof(Latency), nameof(State),
            nameof(FirstSeen), nameof(LastSeen), nameof(Role), nameof(StateDescription), nameof(IsOnline), nameof(IsOffline), nameof(IsUnknown) }) OnPropertyChanged(name);
    }
}
