using Avalonia;
using Avalonia.Controls.ApplicationLifetimes;
using Avalonia.Markup.Xaml;
using Microsoft.Extensions.DependencyInjection;
using Serilog;
using WirelessSecurityAnalyzer.App.ViewModels;
using WirelessSecurityAnalyzer.App.Views;
using WirelessSecurityAnalyzer.Core.Interfaces;
using WirelessSecurityAnalyzer.Core.Analysis.Channels;
using WirelessSecurityAnalyzer.Core.Models;
using WirelessSecurityAnalyzer.Infrastructure.Windows.Services;
using WirelessSecurityAnalyzer.Infrastructure.Windows.Wifi;
using WirelessSecurityAnalyzer.Core.Network;
using WirelessSecurityAnalyzer.Infrastructure.Windows.Network;
using WirelessSecurityAnalyzer.Infrastructure.Windows.Network.Identity;

namespace WirelessSecurityAnalyzer.App;

public partial class App : Application
{
    private ServiceProvider? _services;
    public override void Initialize() => AvaloniaXamlLoader.Load(this);

    public override void OnFrameworkInitializationCompleted()
    {
        if (ApplicationLifetime is IClassicDesktopStyleApplicationLifetime desktop)
        {
            var services = new ServiceCollection();
            services.AddSingleton<ILogger>(Log.Logger);
            services.AddSingleton<WindowsWifiScanner>();
            services.AddSingleton<WifiScanService>(p => new WifiScanService(p.GetRequiredService<WindowsWifiScanner>(), Log.Logger));
            services.AddSingleton<IWifiScanner>(p => p.GetRequiredService<WifiScanService>());
            services.AddSingleton<IWifiScanState>(p => p.GetRequiredService<WifiScanService>());
            services.AddSingleton<IWifiAdapterService>(p => p.GetRequiredService<WindowsWifiScanner>());
            services.AddSingleton<IWifiMonitorService, WifiMonitorService>();
            services.AddSingleton(new ChannelAnalysisOptions());
            services.AddSingleton<IChannelOverlapModel, ChannelOverlapCalculator>();
            services.AddSingleton<IChannelCandidateProvider, WifiChannelCatalog>();
            services.AddSingleton<IChannelAnalyzer, ChannelAnalyzer>();
            services.AddSingleton(new DeviceDiscoveryOptions { ResolveHostnames = false });
            services.AddSingleton(new DeviceIdentityOptions());
            services.AddSingleton<DeviceIdentityCache>();
            services.AddSingleton<MacVendorResolver>();
            services.AddSingleton<IIdentityDatagramClient, IdentityDatagramClient>();
            services.AddSingleton<IUpnpDescriptionClient, UpnpDescriptionClient>();
            services.AddSingleton<IDeviceNameResolver, LocalComputerNameResolver>();
            services.AddSingleton<IDeviceNameResolver, ReverseDnsNameResolver>();
            services.AddSingleton<IDeviceNameResolver, NetBiosNameResolver>();
            services.AddSingleton<IDeviceNameResolver, LlmnrNameResolver>();
            services.AddSingleton<INetworkIdentityResolver, MdnsNameResolver>();
            services.AddSingleton<INetworkIdentityResolver, SsdpDeviceResolver>();
            services.AddSingleton<IDeviceIdentityResolver, DeviceIdentityResolver>();
            services.AddSingleton<ILocalNetworkService, WindowsLocalNetworkService>();
            services.AddSingleton<INeighborTableReader, WindowsNeighborTableReader>();
            services.AddSingleton<IHostProbe, PingHostProbe>();
            services.AddSingleton<IHostnameResolver, HostnameResolver>();
            services.AddSingleton<IDeviceDiscoveryService, WindowsDeviceDiscoveryService>();
            services.AddSingleton<IDeviceMonitorService, DeviceMonitorService>();
            services.AddSingleton<ISystemSettingsService, WindowsSystemSettingsService>();
            services.AddSingleton<AccessPointsViewModel>();
            services.AddSingleton<DashboardViewModel>();
            services.AddSingleton<ChannelsViewModel>();
            services.AddSingleton<SignalViewModel>();
            services.AddSingleton<DevicesViewModel>();
            services.AddSingleton<SettingsViewModel>();
            services.AddSingleton<MainWindowViewModel>();
            _services = services.BuildServiceProvider(new ServiceProviderOptions { ValidateOnBuild = true, ValidateScopes = true });
            var viewModel = _services.GetRequiredService<MainWindowViewModel>();
            desktop.MainWindow = new MainWindow { DataContext = viewModel };
            desktop.Exit += (_, _) =>
            {
                viewModel.Stop();
                _services.Dispose();
                Log.Information("Application exit");
            };
        }
        base.OnFrameworkInitializationCompleted();
    }
}
