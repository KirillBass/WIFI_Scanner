using System.Net.Sockets;
using System.Security.Authentication;
using Serilog;
using WirelessSecurityAnalyzer.Core.Models;
using WirelessSecurityAnalyzer.Core.NetworkAudit;

namespace WirelessSecurityAnalyzer.Infrastructure.Windows.NetworkAudit;

public sealed class ServiceDetectionEngine(IPortScanner scanner, IEnumerable<IServiceDetector> detectors,
    NetworkAuditOptions options, ILogger logger) : IServiceDetectionEngine
{
    private readonly IServiceDetector[] _detectors = detectors.ToArray();
    public Task<ServiceIdentity> DetectAsync(LocalNetworkInfo network, PortScanConnection connection, CancellationToken cancellationToken) =>
        DetectCoreAsync(network, connection, cancellationToken, false);
    public Task<ServiceIdentity> DetectTargetedAsync(LocalNetworkInfo network, PortScanConnection connection, CancellationToken cancellationToken) =>
        DetectCoreAsync(network, connection, cancellationToken, true);
    private async Task<ServiceIdentity> DetectCoreAsync(LocalNetworkInfo network, PortScanConnection connection, CancellationToken cancellationToken, bool targeted)
    {
        if (connection.Stream is null || connection.Result.State != PortState.Open) return ServiceIdentity.Unknown;
        using var budget = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
        budget.CancelAfter(options.ServiceBudgetMs);
        var banner = await ReadBannerAsync(connection.Stream, budget.Token).ConfigureAwait(false);
        // Reuse the scan connection for the first active probe if no greeting was consumed.
        // Close it before reconnecting: one worker owns at most one socket at a time.
        var initialAvailable = banner.Length == 0;
        PortScanConnection? active = null;
        async Task<Stream> Open(CancellationToken token)
        {
            if (initialAvailable) { initialAvailable = false; return connection.Stream; }
            await connection.DisposeAsync().ConfigureAwait(false);
            if (active is not null) await active.DisposeAsync().ConfigureAwait(false);
            active = await scanner.ConnectAsync(network, connection.Result.Address, connection.Result.Port,
                TimeSpan.FromMilliseconds(650), token).ConfigureAwait(false);
            return active.Stream ?? throw new IOException("Service connection unavailable.");
        }
        var probe = new ServiceProbe(connection.Result.Address, connection.Result.Port, banner, Open);
        try
        {
            var applicable = _detectors.Where(d => d.IsPassive || d.Name is "HTTP" or "HTTPS" || d.IsPreferred(probe.Port) || targeted && d.Name == "SMB")
                .OrderBy(d => d.IsPassive ? 0 : d.IsPreferred(probe.Port) ? 1 : 2);
            foreach (var detector in applicable)
            {
                if (budget.IsCancellationRequested) break;
                using var deadline = CancellationTokenSource.CreateLinkedTokenSource(budget.Token);
                deadline.CancelAfter(options.ServiceTimeoutMs);
                try
                {
                    var identity = await detector.DetectAsync(probe, deadline.Token).ConfigureAwait(false);
                    if (targeted && detector is FtpServiceDetector && !TargetServiceMatcher.IsConfirmed(identity ?? ServiceIdentity.Unknown))
                        identity = await FtpServiceDetector.ConfirmAmbiguousGreetingAsync(probe, deadline.Token).ConfigureAwait(false) ?? identity;
                    cancellationToken.ThrowIfCancellationRequested();
                    if (identity is not null) return identity;
                }
                catch (Exception ex) when (ex is IOException or SocketException or AuthenticationException or
                    OperationCanceledException or InvalidDataException)
                {
                    cancellationToken.ThrowIfCancellationRequested();
                    logger.Debug("Service probe {Detector} at {Address}:{Port}: {ErrorType}", detector.Name,
                        probe.Address, probe.Port, ex.GetType().Name);
                }
                finally
                {
                    if (active is not null) { await active.DisposeAsync().ConfigureAwait(false); active = null; }
                    if (!initialAvailable) await connection.DisposeAsync().ConfigureAwait(false);
                }
            }
            cancellationToken.ThrowIfCancellationRequested();
            return ServiceIdentity.Unknown;
        }
        finally { if (active is not null) await active.DisposeAsync().ConfigureAwait(false); }
    }
    private async Task<byte[]> ReadBannerAsync(Stream stream, CancellationToken token)
    {
        using var deadline = CancellationTokenSource.CreateLinkedTokenSource(token);
        deadline.CancelAfter(options.BannerTimeoutMs);
        using var collected = new MemoryStream(); var bytes = new byte[4096];
        try
        {
            while (collected.Length < bytes.Length)
            {
                var count = await stream.ReadAsync(bytes.AsMemory(0, bytes.Length - (int)collected.Length), deadline.Token).ConfigureAwait(false);
                if (count == 0) break;
                collected.Write(bytes, 0, count);
                var text = System.Text.Encoding.ASCII.GetString(collected.GetBuffer(), 0, (int)collected.Length);
                if (text.Split('\n').SkipLast(1).Any(line => line.StartsWith("SSH-", StringComparison.Ordinal) ||
                    line.StartsWith("220 ", StringComparison.Ordinal))) break;
            }
        }
        catch (Exception ex) when (ex is IOException or OperationCanceledException) { }
        return collected.ToArray();
    }
}
