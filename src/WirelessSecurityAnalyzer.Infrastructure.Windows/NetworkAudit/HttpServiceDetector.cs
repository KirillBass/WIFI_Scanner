using System.Net.Security;
using System.Security.Authentication;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using WirelessSecurityAnalyzer.Core.NetworkAudit;

namespace WirelessSecurityAnalyzer.Infrastructure.Windows.NetworkAudit;

public sealed class HttpServiceDetector : IServiceDetector
{
    private static readonly string UserAgent = $"WirelessSecurityAnalyzer/{typeof(HttpServiceDetector).Assembly.GetName().Version?.Major}";
    public string Name => "HTTP";
    public bool IsPassive => false;
    public bool IsPreferred(int port) => port is 80 or 8000 or 8008 or 8080 or 8081 or 5985;
    public async Task<ServiceIdentity?> DetectAsync(ServiceProbe probe, CancellationToken cancellationToken) =>
        await ReadAsync(await probe.OpenStreamAsync(cancellationToken).ConfigureAwait(false), probe, false, cancellationToken).ConfigureAwait(false);
    internal static async Task<ServiceIdentity?> ReadAsync(Stream stream, ServiceProbe probe, bool tls, CancellationToken token)
    {
        var request = Encoding.ASCII.GetBytes($"HEAD / HTTP/1.1\r\nHost: {probe.Address}:{probe.Port}\r\nUser-Agent: {UserAgent}\r\nConnection: close\r\n\r\n");
        await stream.WriteAsync(request, token).ConfigureAwait(false);
        var header = Encoding.ASCII.GetString(await ProbeIo.ReadHeaderAsync(stream, token).ConfigureAwait(false));
        var lines = header.Split("\r\n"); var status = lines[0].Split(' ', StringSplitOptions.RemoveEmptyEntries);
        if (status.Length < 2 || status[0] is not ("HTTP/1.0" or "HTTP/1.1") ||
            status[1].Length != 3 || !status[1].All(char.IsAsciiDigit) || !int.TryParse(status[1], out var code) || code is < 100 or > 599) return null;
        var server = lines.Skip(1).FirstOrDefault(l => l.StartsWith("Server:", StringComparison.OrdinalIgnoreCase));
        var value = server is null ? "" : ProbeIo.Clean(server[7..], 256);
        var (product, version) = ProbeIo.HttpProduct(value);
        return new(tls ? "HTTPS" : "HTTP", product, version, ServiceConfidence.High,
            $"{ProbeIo.Clean(lines[0], 160)}" + (server is null ? " · Server не объявлен." : $" · Server: {value}"),
            "HTTP HEAD /; перенаправления не выполнялись. Server - сведения, объявленные сервером.");
    }
}

public sealed class HttpsServiceDetector : IServiceDetector
{
    public string Name => "HTTPS";
    public bool IsPassive => false;
    public bool IsPreferred(int port) => port is 443 or 8443 or 5986 or 465 or 636 or 993 or 995;
    public async Task<ServiceIdentity?> DetectAsync(ServiceProbe probe, CancellationToken cancellationToken)
    {
        var metadata = "";
        await using var tls = new SslStream(await probe.OpenStreamAsync(cancellationToken).ConfigureAwait(false), leaveInnerStreamOpen: true,
            (_, certificate, _, errors) =>
            {
                if (certificate is not null)
                {
                    using var cert = X509CertificateLoader.LoadCertificate(certificate.GetRawCertData());
                    var san = cert.Extensions.FirstOrDefault(e => e.Oid?.Value == "2.5.29.17")?.Format(false);
                    metadata = $"Subject: {ProbeIo.Clean(cert.Subject, 512)}\nIssuer: {ProbeIo.Clean(cert.Issuer, 512)}\nSAN: {ProbeIo.Clean(san, 1024)}\nПроверка сертификата: {errors}. Доверие не подтверждается; сертификат принят только для определения службы.";
                }
                return certificate is not null;
            });
        await tls.AuthenticateAsClientAsync(new SslClientAuthenticationOptions
        {
            TargetHost = probe.Address.ToString(), EnabledSslProtocols = SslProtocols.None,
            ApplicationProtocols = [SslApplicationProtocol.Http11],
            CertificateChainPolicy = new X509ChainPolicy { RevocationMode = X509RevocationMode.NoCheck, DisableCertificateDownloads = true }
        }, cancellationToken).ConfigureAwait(false);
        metadata += $"\nTLS: {tls.SslProtocol} · ALPN: {tls.NegotiatedApplicationProtocol}";
        try
        {
            var http = await HttpServiceDetector.ReadAsync(tls, probe, true, cancellationToken).ConfigureAwait(false);
            if (http is not null) return http with { Metadata = http.Metadata + "\n" + metadata };
        }
        catch (Exception ex) when (ex is IOException or OperationCanceledException or InvalidDataException) { }
        return new("TLS", null, null, ServiceConfidence.High, "Успешное TLS-рукопожатие; HTTP не подтверждён.", metadata);
    }
}
