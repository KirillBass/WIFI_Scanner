using WirelessSecurityAnalyzer.Core.Models;

namespace WirelessSecurityAnalyzer.Core.Interfaces;

public interface IWifiAdapterService
{
    Task<IReadOnlyList<WifiAdapter>> GetAdaptersAsync(CancellationToken cancellationToken = default);
}
