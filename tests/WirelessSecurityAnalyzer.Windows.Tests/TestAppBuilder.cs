using Avalonia;
using Avalonia.Headless;
using Avalonia.Headless.XUnit;

[assembly: AvaloniaTestApplication(typeof(WirelessSecurityAnalyzer.Windows.Tests.TestAppBuilder))]

namespace WirelessSecurityAnalyzer.Windows.Tests;

public static class TestAppBuilder
{
    public static AppBuilder BuildAvaloniaApp() => AppBuilder.Configure<WirelessSecurityAnalyzer.App.App>()
        .UseHeadless(new AvaloniaHeadlessPlatformOptions());
}
