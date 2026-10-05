using Avalonia.Controls;
using Avalonia.Headless.XUnit;
using Avalonia.VisualTree;
using Serilog;
using WirelessSecurityAnalyzer.App.ViewModels;
using WirelessSecurityAnalyzer.App.Views;
using WirelessSecurityAnalyzer.Core.Common;
using WirelessSecurityAnalyzer.Core.Interfaces;
using WirelessSecurityAnalyzer.Core.Models;

namespace WirelessSecurityAnalyzer.Windows.Tests;

public sealed class UiSmokeTests
{
    [AvaloniaFact]
    public void WindowLoadsAllSixPagesAndNativeTable()
    {
        var accessPoints = CreateViewModel(new TestScanner());
        var vm = new MainWindowViewModel(new DashboardViewModel(accessPoints), accessPoints,
            new ChannelsViewModel(), new SignalViewModel(), new DevicesViewModel(), new SettingsViewModel(accessPoints));
        var window = new MainWindow { DataContext = vm };
        try
        {
            window.Show();
            Assert.True(window.GetVisualDescendants().OfType<TableView>().Any());
            vm.SelectedNavigation = null;
            window.UpdateLayout();
            Assert.Same(accessPoints, vm.CurrentPage);
            Type[] expectedViews = [typeof(DashboardView), typeof(AccessPointsView), typeof(ChannelsView),
                typeof(SignalView), typeof(DevicesView), typeof(SettingsView)];
            for (var i = 0; i < vm.Navigation.Count; i++)
            {
                var page = vm.Navigation[i];
                vm.SelectedNavigation = page;
                window.UpdateLayout();
                Assert.Contains(window.GetVisualDescendants(), control => control.GetType() == expectedViews[i]);
                Assert.Same(page.Page, vm.CurrentPage);
            }
        }
        finally { vm.Stop(); window.Close(); }
    }

    [AvaloniaFact]
    public async Task RepeatedScanKeepsRowsAndAppliesSearchAndBandFilter()
    {
        var scanner = new TestScanner { Results = [Point("Alpha", "00:01:02:03:04:05", -40, WifiBand.Ghz2_4), Point("Beta", "00:01:02:03:04:06", -70, WifiBand.Ghz5)] };
        var vm = CreateViewModel(scanner);
        await vm.ScanCommand.ExecuteAsync(null);
        Assert.Equal(2, vm.TotalCount);
        var first = vm.AccessPoints[0];
        scanner.Results = [scanner.Results[0] with { RssiDbm = -60 }, scanner.Results[1]];
        await vm.ScanCommand.ExecuteAsync(null);
        Assert.Same(first, vm.AccessPoints[0]);
        Assert.Equal(-60, first.RssiDbm);
        vm.SearchText = "alpha";
        Assert.Single(vm.AccessPoints);
        vm.SelectedBandIndex = 2;
        Assert.Empty(vm.AccessPoints);
        vm.SearchText = string.Empty;
        Assert.Single(vm.AccessPoints);
        Assert.Equal("Beta", vm.AccessPoints[0].Ssid);
    }

    [AvaloniaFact]
    public async Task PermissionFailurePreservesLastSuccessfulData()
    {
        var scanner = new TestScanner { Results = [Point("Alpha", "00:01:02:03:04:05", -50, WifiBand.Ghz2_4)] };
        var vm = CreateViewModel(scanner);
        await vm.ScanCommand.ExecuteAsync(null);
        scanner.Error = new WifiException(WifiErrorKind.AccessDenied, "native details");
        await vm.ScanCommand.ExecuteAsync(null);
        Assert.Single(vm.AccessPoints);
        Assert.True(vm.HasError);
        Assert.True(vm.IsLocationPermissionRequired);
        Assert.Contains("местоположения", vm.ErrorMessage);
        Assert.DoesNotContain("native details", vm.ErrorMessage);
        Assert.False(vm.IsBusy);
    }

    [AvaloniaFact]
    public async Task CancellationResetsBusyStateAndAllowsAnotherScan()
    {
        var scanner = new TestScanner { WaitForCancellation = true };
        var vm = CreateViewModel(scanner);
        var scan = vm.ScanCommand.ExecuteAsync(null);
        Assert.True(vm.IsBusy);
        vm.ScanCommand.Cancel();
        await scan;
        Assert.False(vm.IsBusy);
        Assert.False(vm.HasError);
        scanner.WaitForCancellation = false;
        await vm.ScanCommand.ExecuteAsync(null);
        Assert.False(vm.HasError);
    }

    private static AccessPointsViewModel CreateViewModel(TestScanner scanner) => new(scanner, scanner, new TestSettings(), new LoggerConfiguration().CreateLogger());
    private static WifiAccessPoint Point(string ssid, string bssid, int rssi, WifiBand band) =>
        new(ssid, bssid, rssi, 90, band == WifiBand.Ghz2_4 ? 2412 : 5180, band == WifiBand.Ghz2_4 ? 1 : 36, band, DateTimeOffset.UtcNow, false);

    // Test-only deterministic scanner. Production registration always uses WindowsWifiScanner.
    private sealed class TestScanner : IWifiScanner, IWifiAdapterService
    {
        public IReadOnlyList<WifiAccessPoint> Results { get; set; } = [];
        public Exception? Error { get; set; }
        public bool WaitForCancellation { get; set; }
        public async Task<IReadOnlyList<WifiAccessPoint>> ScanAsync(CancellationToken cancellationToken = default)
        {
            if (WaitForCancellation) await Task.Delay(Timeout.InfiniteTimeSpan, cancellationToken);
            if (Error is not null) throw Error;
            return Results;
        }
        public Task<IReadOnlyList<WifiAdapter>> GetAdaptersAsync(CancellationToken cancellationToken = default) =>
            Task.FromResult<IReadOnlyList<WifiAdapter>>([new WifiAdapter(Guid.Empty, "Test adapter", WifiAdapterState.Disconnected)]);
    }
    private sealed class TestSettings : ISystemSettingsService { public void OpenLocationSettings() { } }
}
