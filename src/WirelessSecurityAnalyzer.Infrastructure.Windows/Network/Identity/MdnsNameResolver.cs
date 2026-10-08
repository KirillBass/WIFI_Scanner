using System.Net;
using Serilog;
using WirelessSecurityAnalyzer.Core.Interfaces;
using WirelessSecurityAnalyzer.Core.Models;
using WirelessSecurityAnalyzer.Core.Network;

namespace WirelessSecurityAnalyzer.Infrastructure.Windows.Network.Identity;

/// <summary>One-shot legacy-unicast mDNS queries (RFC 6762 5.1/6.7), batched per network.</summary>
public sealed class MdnsNameResolver(IIdentityDatagramClient datagrams, DeviceIdentityOptions options, ILogger logger) : INetworkIdentityResolver
{
    public DeviceNameSource Source => DeviceNameSource.Mdns;
    private static readonly string[] Services = ["_services._dns-sd._udp.local", "_workstation._tcp.local", "_device-info._tcp.local",
        "_airplay._tcp.local", "_googlecast._tcp.local", "_ipp._tcp.local", "_http._tcp.local"];

    public async Task ResolveAsync(LocalNetworkInfo network, IReadOnlyList<NetworkDevice> devices,
        Action<DeviceIdentityUpdate> publish, CancellationToken cancellationToken)
    {
        var remote = devices.Where(d => !d.IsLocalMachine).ToArray();
        if (remote.Length == 0) return;
        var id = DnsPacket.NewId();
        var records = new Dictionary<(string Name, ushort Type, string Value), DnsRecord>();
        var questions = Services.Select(s => new DnsQuestion(s, 12))
            .Concat(remote.Select(d => new DnsQuestion(DnsPacket.Reverse(d.IpAddress), 12))).ToArray();
        var queries = questions.Chunk(16).Select(q => DnsPacket.Query(id, q)).ToArray();
        void Receive(IdentityDatagram packet)
        {
            try
            {
                var message = DnsPacket.Parse(packet.Data);
                if (message.Id != id || !message.IsAnswer) return;
                foreach (var record in message.Records.Where(r => r.Class == 1))
                {
                    var key = (record.Name.ToLowerInvariant(), record.Type, record.Target ?? record.Address?.ToString() ?? "");
                    if (record.Ttl == 0) records.Remove(key);
                    else if (records.Count < 4096) records[key] = record;
                }
                foreach (var update in Match(records.Values.ToArray(), remote)) publish(update);
            }
            catch (FormatException exception) { logger.Debug(exception, "Malformed mDNS response"); }
        }
        var endpoint = new IPEndPoint(IPAddress.Parse("224.0.0.251"), 5353);
        await datagrams.QueryAsync(network, endpoint, queries, options.MulticastWindow, Receive, cancellationToken).ConfigureAwait(false);
        // Some responders omit additional records. Ask for only the missing SRV/TXT/A facts.
        var follow = records.Values.Where(r => r.Type == 12 && r.Target?.EndsWith(".local", StringComparison.OrdinalIgnoreCase) == true)
            .Where(r => r.Target!.Contains("._", StringComparison.Ordinal))
            .SelectMany(r => new[] { new DnsQuestion(r.Target!, 33), new DnsQuestion(r.Target!, 16) })
            .Concat(records.Values.Where(r => r.Type == 33 && r.Target is not null).Select(r => new DnsQuestion(r.Target!, 1)))
            .Where(q => !records.Values.Any(r => r.Type == q.Type && r.Name.Equals(q.Name, StringComparison.OrdinalIgnoreCase)))
            .Distinct().Take(64).ToArray();
        if (follow.Length > 0)
            await datagrams.QueryAsync(network, endpoint, follow.Chunk(16).Select(q => DnsPacket.Query(id, q)).ToArray(),
                options.QueryTimeout, Receive, cancellationToken).ConfigureAwait(false);
    }

    internal static IReadOnlyList<DeviceIdentityUpdate> Match(IReadOnlyList<DnsRecord> records, IReadOnlyList<NetworkDevice> devices)
    {
        var updates = new List<DeviceIdentityUpdate>();
        var addresses = records.Where(r => r.Type == 1 && r.Address is not null && r.Name.EndsWith(".local", StringComparison.OrdinalIgnoreCase))
            .GroupBy(r => r.Address!).ToDictionary(g => g.Key, g => g.OrderBy(r => r.Name, StringComparer.OrdinalIgnoreCase).First().Name);
        var pointers = records.Where(r => r.Type == 12 && r.Target?.EndsWith(".local", StringComparison.OrdinalIgnoreCase) == true)
            .GroupBy(r => r.Name, StringComparer.OrdinalIgnoreCase).ToDictionary(g => g.Key, g => g.First().Target, StringComparer.OrdinalIgnoreCase);
        var services = records.Where(r => r.Type == 33 && r.Target is not null).GroupBy(r => r.Target!, StringComparer.OrdinalIgnoreCase)
            .ToDictionary(g => g.Key, g => g.OrderBy(r => r.Name, StringComparer.OrdinalIgnoreCase).First(), StringComparer.OrdinalIgnoreCase);
        var texts = records.Where(r => r.Type == 16).GroupBy(r => r.Name, StringComparer.OrdinalIgnoreCase)
            .ToDictionary(g => g.Key, g => g.First(), StringComparer.OrdinalIgnoreCase);
        foreach (var device in devices)
        {
            var reverse = DnsPacket.Reverse(device.IpAddress);
            var hostname = addresses.GetValueOrDefault(device.IpAddress) ?? pointers.GetValueOrDefault(reverse);
            if (hostname is null) continue;
            var srv = services.GetValueOrDefault(hostname);
            var txt = srv is null ? null : texts.GetValueOrDefault(srv.Name);
            string? Value(params string[] keys) => keys.Select(k => txt?.Text.GetValueOrDefault(k)).Select(DeviceIdentityMerger.Clean).FirstOrDefault(v => v is not null);
            // DNS-SD instance labels are published names, not a guess from a manufacturer.
            var instance = srv?.Name.IndexOf("._", StringComparison.Ordinal) is >= 1 and var separator ? srv.Name[..separator] : null;
            var friendly = Value("fn", "ty", "friendlyName") ?? DeviceIdentityMerger.Clean(instance);
            updates.Add(new(device, new()
            {
                Hostname = hostname, HostnameSource = DeviceNameSource.Mdns,
                FriendlyName = friendly, FriendlyNameSource = friendly is null ? DeviceNameSource.None : DeviceNameSource.Mdns,
                ModelName = Value("md", "model", "modelName"), DeviceType = Value("deviceType"), MetadataSource = DeviceNameSource.Mdns
            }));
        }
        return updates;
    }
}
