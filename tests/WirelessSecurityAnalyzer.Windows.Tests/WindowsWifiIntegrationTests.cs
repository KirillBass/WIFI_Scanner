using System.Net.NetworkInformation;
using System.Runtime.CompilerServices;
using Serilog;
using WirelessSecurityAnalyzer.Infrastructure.Windows.Wifi;

namespace WirelessSecurityAnalyzer.Windows.Tests;

public sealed class WindowsWifiFactAttribute : FactAttribute
{
    public WindowsWifiFactAttribute([CallerFilePath] string? sourceFilePath = null,
        [CallerLineNumber] int sourceLineNumber = -1) : base(sourceFilePath, sourceLineNumber)
    {
        if (!OperatingSystem.IsWindows()) Skip = "Native Wi-Fi integration requires Windows.";
        else if (Environment.GetEnvironmentVariable("WSA_RUN_WIFI_INTEGRATION_TESTS") != "1")
            Skip = "Opt-in integration test: set WSA_RUN_WIFI_INTEGRATION_TESTS=1.";
        else if (!NetworkInterface.GetAllNetworkInterfaces().Any(n => n.NetworkInterfaceType == NetworkInterfaceType.Wireless80211))
            Skip = "No Wi-Fi adapter was found.";
    }
}

public sealed class WindowsWifiIntegrationTests
{
    [WindowsWifiFact]
    [Trait("Category", "WindowsIntegration")]
    public async Task NativeScanCanBeRepeatedOnRealHardware()
    {
        var scanner = new WindowsWifiScanner(new LoggerConfiguration().CreateLogger());
        using var timeout = new CancellationTokenSource(TimeSpan.FromSeconds(60));
        Assert.NotEmpty(await scanner.GetAdaptersAsync(timeout.Token));
        var first = await scanner.ScanAsync(timeout.Token);
        var second = await scanner.ScanAsync(timeout.Token);
        foreach (var point in first.Concat(second))
        {
            Assert.Matches("^([0-9A-F]{2}:){5}[0-9A-F]{2}$", point.Bssid);
            Assert.InRange(point.LinkQuality, 0u, 100u);
            Assert.True(point.FrequencyMhz > 0);
        }
    }
}
