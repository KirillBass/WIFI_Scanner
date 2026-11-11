using System.Text;
using System.Text.RegularExpressions;
using WirelessSecurityAnalyzer.Core.NetworkAudit;

namespace WirelessSecurityAnalyzer.Infrastructure.Windows.NetworkAudit;

internal static partial class ProbeIo
{
    public static async Task<byte[]> ReadHeaderAsync(Stream stream, CancellationToken token)
    {
        using var buffer = new MemoryStream();
        var chunk = new byte[1024];
        while (buffer.Length < NetworkAuditOptions.MaximumResponseBytes)
        {
            var count = await stream.ReadAsync(chunk.AsMemory(0, Math.Min(chunk.Length,
                NetworkAuditOptions.MaximumResponseBytes - (int)buffer.Length)), token).ConfigureAwait(false);
            if (count == 0) break;
            buffer.Write(chunk, 0, count);
            var data = buffer.GetBuffer().AsSpan(0, (int)buffer.Length);
            var end = data.IndexOf("\r\n\r\n"u8);
            if (end >= 0) return data[..(end + 4)].ToArray();
        }
        throw new InvalidDataException("HTTP header incomplete or too large.");
    }
    public static async Task<byte[]> ReadFrameAsync(Stream stream, bool tpkt, CancellationToken token)
    {
        var header = new byte[4];
        await stream.ReadExactlyAsync(header, token).ConfigureAwait(false);
        if ((tpkt && (header[0] != 3 || header[1] != 0)) || (!tpkt && header[0] != 0))
            throw new InvalidDataException("Invalid frame.");
        var length = tpkt ? (header[2] << 8 | header[3]) - 4 : header[1] << 16 | header[2] << 8 | header[3];
        if (length is < 1 or > NetworkAuditOptions.MaximumResponseBytes) throw new InvalidDataException("Invalid frame length.");
        var payload = new byte[length + 4]; header.CopyTo(payload, 0);
        await stream.ReadExactlyAsync(payload.AsMemory(4), token).ConfigureAwait(false);
        return payload;
    }
    public static string Clean(string? text, int max = 1024)
    {
        if (string.IsNullOrEmpty(text)) return "";
        text = text[..Math.Min(text.Length, max)];
        return new string(text.Select(c => c >= ' ' && c != '\u007f' ? c : ' ').ToArray()).Trim();
    }
    public static string BannerText(ReadOnlyMemory<byte> banner) => Encoding.ASCII.GetString(banner.Span);
    [GeneratedRegex(@"(?:^|\s)(Microsoft-IIS|Apache|nginx)(?=$|[\s/])(?:/([0-9][0-9A-Za-z.\-_]*))?", RegexOptions.IgnoreCase | RegexOptions.CultureInvariant)]
    private static partial Regex ProductPattern();
    public static (string? Product, string? Version) HttpProduct(string server)
    {
        var match = ProductPattern().Match(server);
        if (!match.Success) return (null, null);
        return (match.Groups[1].Value.ToLowerInvariant() switch { "microsoft-iis" => "Microsoft IIS", "apache" => "Apache", _ => "nginx" },
            match.Groups[2].Success ? match.Groups[2].Value : null);
    }
}
