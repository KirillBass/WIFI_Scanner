using WirelessSecurityAnalyzer.Core.Models;

namespace WirelessSecurityAnalyzer.Core.Interfaces;

/// <summary>The latest successful scan, shared by all application pages.</summary>
public interface IWifiScanState
{
    WifiScanSnapshot? Current { get; }
    event EventHandler<WifiScanSnapshot>? Updated;
}
