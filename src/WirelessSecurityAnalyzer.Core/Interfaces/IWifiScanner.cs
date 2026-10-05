using WirelessSecurityAnalyzer.Core.Models;

namespace WirelessSecurityAnalyzer.Core.Interfaces;

public interface IWifiScanner
{
    Task<IReadOnlyList<WifiAccessPoint>> ScanAsync(CancellationToken cancellationToken = default);
}
