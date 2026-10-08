using System.Net;
using System.Text;
using Serilog;
using WirelessSecurityAnalyzer.Core.Interfaces;
using WirelessSecurityAnalyzer.Core.Models;

namespace WirelessSecurityAnalyzer.Infrastructure.Windows.Network.Identity;

public sealed class SsdpDeviceResolver(IIdentityDatagramClient datagrams, IUpnpDescriptionClient descriptions,
    DeviceIdentityOptions options, ILogger logger) : INetworkIdentityResolver
{
    public DeviceNameSource Source => DeviceNameSource.Ssdp;
    internal const string Search = "M-SEARCH * HTTP/1.1\r\nHOST: 239.255.255.250:1900\r\nMAN: \"ssdp:discover\"\r\nMX: 1\r\nST: upnp:rootdevice\r\n\r\n";

    public async Task ResolveAsync(LocalNetworkInfo network, IReadOnlyList<NetworkDevice> devices,
        Action<DeviceIdentityUpdate> publish, CancellationToken cancellationToken)
    {
        var found = devices.Where(d => !d.IsLocalMachine).ToDictionary(d => d.IpAddress);
        if (found.Count == 0) return;
        var locations = new Dictionary<string, (NetworkDevice Device, Uri Location)>();
        await datagrams.QueryAsync(network, new(IPAddress.Parse("239.255.255.250"), 1900), [Encoding.ASCII.GetBytes(Search)], options.MulticastWindow, packet =>
        {
            if (!found.TryGetValue(packet.Sender.Address, out var device) || locations.Count >= options.MaxDescriptions) return;
            var location = ParseLocation(packet.Data);
            if (location is not null && UpnpDescriptionClient.IsAllowed(network, device.IpAddress, location))
                locations.TryAdd(location.AbsoluteUri, (device, location));
        }, cancellationToken).ConfigureAwait(false);
        await Parallel.ForEachAsync(locations.Values,
            new ParallelOptions { MaxDegreeOfParallelism = options.MaxConcurrency, CancellationToken = cancellationToken }, async (entry, token) =>
            {
                try
                {
                    var identity = await descriptions.ReadAsync(network, entry.Device.IpAddress, entry.Location, token).ConfigureAwait(false);
                    if (identity is not null) publish(new(entry.Device, identity));
                }
                catch (OperationCanceledException) when (token.IsCancellationRequested) { throw; }
                catch (Exception exception) { logger.Debug(exception, "UPnP description unavailable or invalid"); }
            }).ConfigureAwait(false);
    }

    internal static Uri? ParseLocation(byte[] packet)
    {
        if (packet.Length is < 16 or > 16384) return null;
        var lines = Encoding.ASCII.GetString(packet).Split("\r\n", StringSplitOptions.None);
        if (!lines[0].StartsWith("HTTP/1.1 200 ", StringComparison.OrdinalIgnoreCase) && !lines[0].Equals("HTTP/1.1 200", StringComparison.OrdinalIgnoreCase)) return null;
        var headers = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
        foreach (var line in lines.Skip(1))
        {
            if (line.Length == 0) break;
            var split = line.IndexOf(':');
            if (split <= 0 || !headers.TryAdd(line[..split].Trim(), line[(split + 1)..].Trim())) return null;
        }
        return headers.TryGetValue("LOCATION", out var value) && Uri.TryCreate(value, UriKind.Absolute, out var uri) ? uri : null;
    }
}
