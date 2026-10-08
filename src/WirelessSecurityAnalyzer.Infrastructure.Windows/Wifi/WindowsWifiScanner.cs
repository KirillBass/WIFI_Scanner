using Serilog;
using WirelessSecurityAnalyzer.Core.Common;
using WirelessSecurityAnalyzer.Core.Interfaces;
using WirelessSecurityAnalyzer.Core.Models;
using WirelessSecurityAnalyzer.Infrastructure.Windows.NativeWifi;
using WirelessSecurityAnalyzer.Infrastructure.Windows.Network.Identity;

namespace WirelessSecurityAnalyzer.Infrastructure.Windows.Wifi;

public sealed class WindowsWifiScanner(ILogger logger, MacVendorResolver? vendorResolver = null) : IWifiScanner, IWifiAdapterService
{
    private readonly MacVendorResolver _vendorResolver = vendorResolver ?? new MacVendorResolver();
    private readonly SemaphoreSlim _scanGate = new(1, 1);
    private static readonly TimeSpan ScanTimeout = TimeSpan.FromSeconds(10);

    public Task<IReadOnlyList<WifiAdapter>> GetAdaptersAsync(CancellationToken cancellationToken = default) =>
        Task.Run<IReadOnlyList<WifiAdapter>>(() =>
        {
            cancellationToken.ThrowIfCancellationRequested();
            using var client = new NativeWifiClient(logger, _vendorResolver);
            var adapters = client.GetAdapters();
            logger.Information("Detected {AdapterCount} WLAN interfaces: {Adapters}", adapters.Count,
                adapters.Select(a => new { a.Description, a.State }));
            return adapters;
        }, cancellationToken);

    public async Task<IReadOnlyList<WifiAccessPoint>> ScanAsync(CancellationToken cancellationToken = default)
    {
        await _scanGate.WaitAsync(cancellationToken).ConfigureAwait(false);
        try
        {
            return await Task.Run(async () =>
            {
                using var client = new NativeWifiClient(logger, _vendorResolver);
                var adapters = client.GetAdapters();
                if (adapters.Count == 0)
                    throw new WifiException(WifiErrorKind.NoAdapter, "No WLAN adapters were found.");
                var ready = adapters.Where(a => a.State != WifiAdapterState.NotReady).ToArray();
                if (ready.Length == 0)
                    throw new WifiException(WifiErrorKind.RadioOff, "All WLAN adapters are disabled or not ready.");

                logger.Information("WLAN scan started on {AdapterCount} interfaces", ready.Length);
                var all = new List<WifiAccessPoint>();
                WifiException? failure = null;
                var successfulScans = 0;
                foreach (var adapter in ready)
                {
                    cancellationToken.ThrowIfCancellationRequested();
                    try
                    {
                        all.AddRange(await client.ScanAsync(adapter, ScanTimeout, cancellationToken).ConfigureAwait(false));
                        successfulScans++;
                    }
                    catch (WifiException exception)
                    {
                        logger.Warning(exception, "WLAN scan failed on adapter {AdapterId}", adapter.Id);
                        failure = exception;
                    }
                }
                if (successfulScans == 0 && failure is not null) throw failure;
                IReadOnlyList<WifiAccessPoint> result = all.GroupBy(ap => ap.Bssid, StringComparer.OrdinalIgnoreCase)
                    .Select(g => g.OrderByDescending(ap => ap.RssiDbm).First())
                    .OrderByDescending(ap => ap.RssiDbm).ToArray();
                logger.Information("WLAN scan completed: {BssCount} BSS, {FailedAdapters} failed adapters", result.Count,
                    ready.Length - successfulScans);
                return result;
            }, cancellationToken).ConfigureAwait(false);
        }
        finally { _scanGate.Release(); }
    }
}
