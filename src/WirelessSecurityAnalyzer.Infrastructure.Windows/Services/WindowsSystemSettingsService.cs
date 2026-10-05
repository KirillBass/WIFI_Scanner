using System.Diagnostics;
using WirelessSecurityAnalyzer.Core.Common;
using WirelessSecurityAnalyzer.Core.Interfaces;

namespace WirelessSecurityAnalyzer.Infrastructure.Windows.Services;

public sealed class WindowsSystemSettingsService : ISystemSettingsService
{
    public void OpenLocationSettings()
    {
        if (!OperatingSystem.IsWindows())
            throw new WifiException(WifiErrorKind.UnsupportedPlatform, "Windows Settings are unavailable on this platform.");
        Process.Start(new ProcessStartInfo("ms-settings:privacy-location") { UseShellExecute = true });
    }
}
