using System.Text;
using System.Text.RegularExpressions;
using WirelessSecurityAnalyzer.Core.NetworkAudit;

namespace WirelessSecurityAnalyzer.Infrastructure.Windows.NetworkAudit;

public sealed partial class SshServiceDetector : IServiceDetector
{
    public string Name => "SSH";
    public bool IsPassive => true;
    public bool IsPreferred(int port) => port == 22;
    public Task<ServiceIdentity?> DetectAsync(ServiceProbe probe, CancellationToken cancellationToken)
    {
        foreach (var line in ProbeIo.BannerText(probe.Banner).Split('\n'))
        {
            var banner = line.TrimEnd('\r');
            if (banner.Length > 253 || banner.Contains('\0')) continue;
            var match = SshBanner().Match(banner);
            if (!match.Success) continue;
            var software = match.Groups[1].Value; string? product = null, version = null;
            foreach (var name in new[] { "OpenSSH", "dropbear", "libssh" })
                if (software.StartsWith(name + "_", StringComparison.OrdinalIgnoreCase))
                { product = name == "dropbear" ? "Dropbear" : name; version = software[(name.Length + 1)..]; break; }
            return Task.FromResult<ServiceIdentity?>(new("SSH", product, version, ServiceConfidence.High, ProbeIo.Clean(banner, 255)));
        }
        return Task.FromResult<ServiceIdentity?>(null);
    }
    [GeneratedRegex(@"^SSH-(?:2\.0|1\.99)-([!-~]+)(?: .*)?$", RegexOptions.CultureInvariant)]
    private static partial Regex SshBanner();
}
public sealed partial class FtpServiceDetector : IServiceDetector
{
    public string Name => "FTP";
    public bool IsPassive => true;
    public bool IsPreferred(int port) => port == 21;
    public Task<ServiceIdentity?> DetectAsync(ServiceProbe probe, CancellationToken cancellationToken)
    {
        var text = ProbeIo.BannerText(probe.Banner);
        var lines = text.Split('\n').SkipLast(1).Select(l => l.TrimEnd('\r')).ToArray();
        var lastLine = Array.FindIndex(lines, l => l.StartsWith("220 ", StringComparison.Ordinal));
        if (lastLine < 0 || text.Contains("SMTP", StringComparison.OrdinalIgnoreCase)) return Task.FromResult<ServiceIdentity?>(null);
        var line = lines[lastLine];
        var productLine = lines.Take(lastLine + 1).FirstOrDefault(l => FtpProduct().IsMatch(l));
        var known = FtpProduct().Match(productLine ?? line);
        // A generic 220 greeting can belong to SMTP. Require FTP evidence or its standard port.
        if (!known.Success && !text.Contains("FTP", StringComparison.OrdinalIgnoreCase) && probe.Port != 21)
            return Task.FromResult<ServiceIdentity?>(null);
        return Task.FromResult<ServiceIdentity?>(new("FTP", known.Success ? known.Groups[1].Value : null,
            known.Groups[2].Success ? known.Groups[2].Value : null,
            known.Success || text.Contains("FTP", StringComparison.OrdinalIgnoreCase) ? ServiceConfidence.High : ServiceConfidence.Medium,
            ProbeIo.Clean(productLine ?? line, 512), "Получено приветствие 220. Вход не выполнялся."));
    }
    // Used only by an explicitly started targeted audit. A bare 220 is also possible in SMTP.
    // SYST asks for the FTP system type without logging in or accessing resources.
    internal static async Task<ServiceIdentity?> ConfirmAmbiguousGreetingAsync(ServiceProbe probe, CancellationToken token)
    {
        var greeting = ProbeIo.BannerText(probe.Banner);
        if (greeting.Contains("SMTP", StringComparison.OrdinalIgnoreCase) ||
            !greeting.Split('\n').Any(line => line.StartsWith("220 ", StringComparison.Ordinal))) return null;
        var stream = await probe.OpenStreamAsync(token).ConfigureAwait(false);
        await stream.WriteAsync("SYST\r\n"u8.ToArray(), token).ConfigureAwait(false);
        using var collected = new MemoryStream();
        var chunk = new byte[512];
        while (collected.Length < 4096)
        {
            var read = await stream.ReadAsync(chunk.AsMemory(0, Math.Min(chunk.Length, 4096 - (int)collected.Length)), token).ConfigureAwait(false);
            if (read == 0) return null;
            collected.Write(chunk, 0, read);
            var lines = Encoding.ASCII.GetString(collected.GetBuffer(), 0, (int)collected.Length).Split('\n').SkipLast(1);
            foreach (var raw in lines)
            {
                var line = raw.TrimEnd('\r');
                if (line.StartsWith("215 ", StringComparison.Ordinal) && line.Length > 4)
                    return new("FTP", null, null, ServiceConfidence.High, ProbeIo.Clean(line, 512),
                        "Приветствие 220 и ответ на SYST. Вход и запрос ресурсов не выполнялись.");
                if (line.Length >= 4 && line[0] is '4' or '5' && line[1..3].All(char.IsAsciiDigit) && line[3] == ' ') return null;
            }
        }
        return null;
    }
    [GeneratedRegex(@"(?:^|[\s(])(?:220-)?(vsFTPd|ProFTPD|FileZilla|Pure-FTPd|Microsoft FTP Service)(?=$|[\s/)])(?:[ /]+([0-9][0-9A-Za-z.\-_]*))?", RegexOptions.IgnoreCase | RegexOptions.CultureInvariant)]
    private static partial Regex FtpProduct();
}
public sealed class GenericBannerServiceDetector : IServiceDetector
{
    public string Name => "Banner";
    public bool IsPassive => true;
    public bool IsPreferred(int port) => false;
    public Task<ServiceIdentity?> DetectAsync(ServiceProbe probe, CancellationToken cancellationToken)
    {
        var line = ProbeIo.BannerText(probe.Banner).Split('\n').Select(l => l.TrimEnd('\r'))
            .FirstOrDefault(l => l.StartsWith("220 ", StringComparison.Ordinal) && l.Contains("SMTP", StringComparison.OrdinalIgnoreCase));
        return Task.FromResult<ServiceIdentity?>(line is null ? null :
            new("SMTP", null, null, ServiceConfidence.High, ProbeIo.Clean(line, 512), "Пассивное приветствие; команды SMTP не отправлялись."));
    }
}
