using System.Globalization;
using WirelessSecurityAnalyzer.Core.Models;

namespace WirelessSecurityAnalyzer.Core.NetworkAudit;

public static class PortScanProfiles
{
    private static readonly int[] QuickPorts = [21,22,23,25,53,80,110,135,139,143,389,443,445,465,587,636,
        993,995,1433,3306,3389,5432,5900,5985,5986,8000,8080,8443];
    public static IReadOnlyList<int> GetPorts(PortProfile profile, string custom = "") => profile switch
    {
        PortProfile.Quick => Array.AsReadOnly(QuickPorts),
        PortProfile.Standard => Array.AsReadOnly(Enumerable.Range(1,1024).Concat(QuickPorts).Distinct().Order().ToArray()),
        PortProfile.Full => Array.AsReadOnly(Enumerable.Range(1,65535).ToArray()),
        PortProfile.Custom => Parse(custom),
        PortProfile.Targeted => TargetServiceProfile.GetPorts(custom),
        _ => throw new ArgumentException("Неизвестный профиль портов.")
    };
    public static IReadOnlyList<int> GetPorts(AuditRequest request)
    {
        var ports = GetPorts(request.Profile, request.CustomPorts);
        return string.IsNullOrWhiteSpace(request.AdditionalPorts) ? ports :
            Array.AsReadOnly(ports.Concat(Parse(request.AdditionalPorts)).Distinct().Order().ToArray());
    }
    public static IReadOnlyList<int> Parse(string text)
    {
        if (text.Length > 8192) throw new ArgumentException("Список портов слишком длинный.");
        var ports = new SortedSet<int>();
        foreach (var token in text.Split([',',';',' ','\t','\r','\n'], StringSplitOptions.RemoveEmptyEntries))
        {
            var bounds = token.Split('-');
            if (bounds.Length is < 1 or > 2 || !ReadPort(bounds[0], out var first) ||
                !ReadPort(bounds[^1], out var last) || last < first)
                throw new ArgumentException($"Некорректный порт или диапазон: {token}. Допустимо 1–65535.");
            for (var port = first; port <= last; port++) ports.Add(port);
        }
        if (ports.Count == 0) throw new ArgumentException("Укажите порты, например: 22,80,443,8000-8010.");
        return Array.AsReadOnly(ports.ToArray());
    }
    public static string Describe(IEnumerable<int> ports)
    {
        var sorted = ports.Distinct().Order().ToArray();
        var ranges = new List<string>();
        for (var i = 0; i < sorted.Length; i++)
        {
            var first = sorted[i];
            while (i + 1 < sorted.Length && sorted[i + 1] == sorted[i] + 1) i++;
            ranges.Add(first == sorted[i] ? first.ToString(CultureInfo.InvariantCulture) : $"{first}-{sorted[i]}");
        }
        return string.Join(", ", ranges);
    }
    private static bool ReadPort(string text, out int port) =>
        int.TryParse(text, NumberStyles.None, CultureInfo.InvariantCulture, out port) && port is >= 1 and <= 65535;
}

public sealed class NetworkAuditOptions
{
    public int ServiceTimeoutMs { get; init; } = 1500;
    public int ServiceBudgetMs { get; init; } = 6000;
    public int BannerTimeoutMs { get; init; } = 150;
    public TimeSpan TargetDiscoveryMaxAge { get; init; } = TimeSpan.FromMinutes(2);
    public const int MaximumResponseBytes = 65536;
    public void Validate(AuditRequest request)
    {
        if (request.Concurrency is < 1 or > 128) throw new ArgumentException("Параллелизм: от 1 до 128 подключений.");
        if (request.ConnectTimeoutMs is < 100 or > 10000) throw new ArgumentException("Таймаут TCP: от 100 до 10000 мс.");
        if (TargetDiscoveryMaxAge <= TimeSpan.Zero) throw new ArgumentException("Некорректный срок актуальности обнаруженных узлов.");
        if (ServiceTimeoutMs is < 50 or > 10000 || ServiceBudgetMs < ServiceTimeoutMs || BannerTimeoutMs is < 10 or > 2000)
            throw new ArgumentException("Некорректные таймауты определения служб.");
    }
}

public static class AuditTargets
{
    public static IReadOnlyList<AuditTarget> Create(NetworkSession session, DeviceMonitorSnapshot discovered, bool includeLocal)
    {
        if (!session.IsReadyForAudit || session.Network is not { } network)
            throw new InvalidOperationException("Подключитесь к Wi-Fi и дождитесь получения IPv4.");
        if (discovered.Network?.HasSameContext(network) != true || discovered.Devices.Count == 0 ||
            discovered.SessionId != Guid.Empty && discovered.SessionId != session.SessionId)
            throw new InvalidOperationException("Сначала обновите список устройств текущей сети.");
        var targets = new Dictionary<System.Net.IPAddress, AuditTarget>();
        foreach (var device in discovered.Devices.GroupBy(d => d.IpAddress)
            .Select(g => g.OrderByDescending(d => d.State == DeviceState.Online)
                .ThenByDescending(d => d.LastSeen).ThenByDescending(d => d.FirstSeen).First()))
            if (network.Subnet.ContainsHost(device.IpAddress) && (includeLocal || !device.IpAddress.Equals(network.LocalIpv4)))
                targets[device.IpAddress] = new(device.IpAddress, device.DisplayName,
                    device.IpAddress.Equals(network.LocalIpv4), Equals(device.IpAddress, network.Gateway))
                { KnownHostnames = new[] { device.Identity?.Hostname, device.Hostname }.OfType<string>()
                    .Where(n => Uri.CheckHostName(n.TrimEnd('.')) == UriHostNameType.Dns).Distinct(StringComparer.OrdinalIgnoreCase).Take(4).ToArray() };
        if (!discovered.Devices.Any(d => network.Subnet.ContainsHost(d.IpAddress)))
            throw new InvalidOperationException("Сначала обновите список устройств текущей сети.");
        if (includeLocal) targets.TryAdd(network.LocalIpv4, new(network.LocalIpv4, Environment.MachineName, true, Equals(network.LocalIpv4, network.Gateway)));
        if (network.Gateway is { } gateway && network.Subnet.ContainsHost(gateway) && (includeLocal || !gateway.Equals(network.LocalIpv4)))
            targets.TryAdd(gateway, new(gateway, "Шлюз", gateway.Equals(network.LocalIpv4), true));
        if (targets.Count == 0) throw new InvalidOperationException("Нет целей аудита. Включите этот компьютер или обновите устройства.");
        return Array.AsReadOnly(targets.Values.OrderBy(t => Convert.ToHexString(t.Address.GetAddressBytes()), StringComparer.Ordinal).ToArray());
    }
}
