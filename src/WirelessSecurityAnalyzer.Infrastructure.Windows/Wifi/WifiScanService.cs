using Serilog;
using WirelessSecurityAnalyzer.Core.Interfaces;
using WirelessSecurityAnalyzer.Core.Models;

namespace WirelessSecurityAnalyzer.Infrastructure.Windows.Wifi;

/// <summary>Coordinates manual/automatic scans and publishes immutable successful snapshots.</summary>
public sealed class WifiScanService(IWifiScanner scanner, ILogger logger) : IWifiScanner, IWifiScanState
{
    private readonly SemaphoreSlim _gate = new(1, 1);
    private WifiScanSnapshot? _current;
    private long _version;
    public WifiScanSnapshot? Current => Volatile.Read(ref _current);
    public event EventHandler<WifiScanSnapshot>? Updated;

    public async Task<IReadOnlyList<WifiAccessPoint>> ScanAsync(CancellationToken cancellationToken = default)
    {
        await _gate.WaitAsync(cancellationToken).ConfigureAwait(false);
        try
        {
            var results = await scanner.ScanAsync(cancellationToken).ConfigureAwait(false);
            cancellationToken.ThrowIfCancellationRequested();
            var snapshot = new WifiScanSnapshot(++_version, DateTimeOffset.UtcNow,
                Array.AsReadOnly(results.ToArray()));
            Volatile.Write(ref _current, snapshot);
            if (Updated is { } handlers)
                foreach (EventHandler<WifiScanSnapshot> handler in handlers.GetInvocationList())
                    try { handler(this, snapshot); }
                    catch (Exception exception) { logger.Error(exception, "Scan snapshot subscriber failed"); }
            return snapshot.AccessPoints;
        }
        finally { _gate.Release(); }
    }
}
