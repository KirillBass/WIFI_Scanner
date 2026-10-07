using WirelessSecurityAnalyzer.Core.Models;

namespace WirelessSecurityAnalyzer.Core.Interfaces;

public interface IWifiMonitorService
{
    bool IsMonitoring { get; }
    WifiMonitorSnapshot Current { get; }
    event EventHandler<WifiMonitorSnapshot>? Updated;
    Task StartAsync(string bssid, TimeSpan? interval = null, CancellationToken cancellationToken = default);
    Task StopAsync();
    WifiMonitorSnapshot GetHistory(string bssid);
    void ClearHistory(string bssid);
}
