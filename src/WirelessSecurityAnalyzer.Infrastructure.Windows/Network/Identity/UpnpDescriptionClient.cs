using System.Net;
using System.Net.Sockets;
using System.Xml;
using System.Xml.Linq;
using WirelessSecurityAnalyzer.Core.Models;
using WirelessSecurityAnalyzer.Core.Network;

namespace WirelessSecurityAnalyzer.Infrastructure.Windows.Network.Identity;

public interface IUpnpDescriptionClient
{
    Task<DeviceIdentity?> ReadAsync(LocalNetworkInfo network, IPAddress responder, Uri location, CancellationToken cancellationToken);
}

public sealed class UpnpDescriptionClient(DeviceIdentityOptions options) : IUpnpDescriptionClient
{
    public async Task<DeviceIdentity?> ReadAsync(LocalNetworkInfo network, IPAddress responder, Uri location, CancellationToken cancellationToken)
    {
        if (!IsAllowed(network, responder, location)) return null;
        using var deadline = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
        deadline.CancelAfter(options.QueryTimeout);
        using var handler = new SocketsHttpHandler
        {
            AllowAutoRedirect = false, UseProxy = false, UseCookies = false,
            ConnectTimeout = options.QueryTimeout, MaxResponseHeadersLength = 16,
            ConnectCallback = async (context, token) =>
            {
                // Use the already validated literal address; never ask DNS to resolve LOCATION.
                if (context.DnsEndPoint.Port != location.Port) throw new HttpRequestException("Unexpected UPnP destination.");
                var socket = new Socket(AddressFamily.InterNetwork, SocketType.Stream, ProtocolType.Tcp);
                try
                {
                    socket.Bind(new IPEndPoint(network.LocalIpv4, 0));
                    IdentitySocketScope.SelectInterface(socket, network);
                    await socket.ConnectAsync(new IPEndPoint(responder, location.Port), token).ConfigureAwait(false);
                    return new NetworkStream(socket, ownsSocket: true);
                }
                catch { socket.Dispose(); throw; }
            }
        };
        using var http = new HttpClient(handler) { Timeout = Timeout.InfiniteTimeSpan };
        using var response = await http.GetAsync(location, HttpCompletionOption.ResponseHeadersRead, deadline.Token).ConfigureAwait(false);
        if (!response.IsSuccessStatusCode || response.Content.Headers.ContentLength > options.MaxDescriptionBytes) return null;
        await using var body = await response.Content.ReadAsStreamAsync(deadline.Token).ConfigureAwait(false);
        using var limited = new MemoryStream(); var buffer = new byte[8192];
        while (true)
        {
            var count = await body.ReadAsync(buffer.AsMemory(0, Math.Min(buffer.Length, options.MaxDescriptionBytes + 1 - (int)limited.Length)), deadline.Token).ConfigureAwait(false);
            if (count == 0) break;
            limited.Write(buffer, 0, count);
            if (limited.Length > options.MaxDescriptionBytes) return null;
        }
        limited.Position = 0;
        return Parse(limited, options.MaxDescriptionBytes);
    }

    internal static bool IsAllowed(LocalNetworkInfo network, IPAddress responder, Uri location) =>
        network.Subnet.ContainsHost(responder) && location.IsAbsoluteUri && location.Scheme is "http" or "https" &&
        location.UserInfo.Length == 0 && location.Fragment.Length == 0 && location.HostNameType == UriHostNameType.IPv4 &&
        IPAddress.TryParse(location.Host, out var target) && target.Equals(responder);

    internal static DeviceIdentity? Parse(Stream xml, int maxBytes)
    {
        using var reader = XmlReader.Create(xml, new XmlReaderSettings
        { DtdProcessing = DtdProcessing.Prohibit, XmlResolver = null, MaxCharactersInDocument = maxBytes, MaxCharactersFromEntities = 0 });
        var document = XDocument.Load(reader);
        if (document.Root?.Name.LocalName != "root") return null;
        var device = document.Root.Elements().FirstOrDefault(e => e.Name.LocalName == "device");
        if (device is null) return null;
        string? Value(string name) => DeviceIdentityMerger.Clean(device.Elements().FirstOrDefault(e => e.Name.LocalName == name)?.Value);
        var friendly = Value("friendlyName"); var vendor = Value("manufacturer");
        return new()
        {
            FriendlyName = friendly, FriendlyNameSource = friendly is null ? DeviceNameSource.None : DeviceNameSource.Ssdp,
            Vendor = vendor, VendorSource = vendor is null ? DeviceVendorSource.None : DeviceVendorSource.Ssdp,
            ModelName = Value("modelName"), ModelDescription = Value("modelDescription"),
            DeviceType = Value("deviceType"), MetadataSource = DeviceNameSource.Ssdp
        };
    }
}
