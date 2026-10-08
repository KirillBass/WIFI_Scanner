using Serilog;
using WirelessSecurityAnalyzer.Core.Common;
using WirelessSecurityAnalyzer.Core.Interfaces;
using WirelessSecurityAnalyzer.Core.Models;

namespace WirelessSecurityAnalyzer.Infrastructure.Windows.Wifi;

/// <summary>Coordinates manual/automatic scans and publishes immutable successful snapshots.</summary>
public sealed class WifiScanService(IWifiScanner scanner, ILogger logger) : IWifiScanner, IWifiScanState
{
    private readonly SemaphoreSlim _gate = new(1, 1);
    private WifiScanSnapshot? _current;
    private WifiScanFailure? _lastFailure;
    private long _version;
    public WifiScanSnapshot? Current => Volatile.Read(ref _current);
    public WifiScanFailure? LastFailure => Volatile.Read(ref _lastFailure);
    public event EventHandler<WifiScanSnapshot>? Updated;
    public event EventHandler<WifiScanFailure>? Failed;

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
            Volatile.Write(ref _lastFailure, null);
            if (Updated is { } handlers)
                foreach (EventHandler<WifiScanSnapshot> handler in handlers.GetInvocationList())
                    try { handler(this, snapshot); }
                    catch (Exception exception) { logger.Error(exception, "Scan snapshot subscriber failed"); }
            return snapshot.AccessPoints;
        }
        catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested) { throw; }
        catch (Exception exception)
        {
            var error = exception as WifiException ?? new WifiException(WifiErrorKind.ScanFailed, "Wi-Fi scan failed.", exception);
            var failure = new WifiScanFailure(++_version, error);
            Volatile.Write(ref _lastFailure, failure);
            if (Failed is { } handlers)
                foreach (EventHandler<WifiScanFailure> handler in handlers.GetInvocationList())
                    try { handler(this, failure); }
                    catch (Exception subscriberError) { logger.Error(subscriberError, "Scan failure subscriber failed"); }
            throw;
        }
        finally { _gate.Release(); }
    }
}
