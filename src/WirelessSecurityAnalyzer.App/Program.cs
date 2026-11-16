using Avalonia;
using Serilog;
using WirelessSecurityAnalyzer.App.Services;

namespace WirelessSecurityAnalyzer.App;

internal static class Program
{
    internal static LoggingSettingsService LoggingSettings { get; } = new();
    [STAThread]
    public static int Main(string[] args)
    {
        Log.Logger = LoggingSettings.InitializeLogger();
        try
        {
            Log.Information("Application startup on {Platform}; version {Version}",
                Environment.OSVersion, typeof(Program).Assembly.GetName().Version);
            AppDomain.CurrentDomain.UnhandledException += (_, e) =>
                Log.Fatal(e.ExceptionObject as Exception, "Unhandled application exception");
            return BuildAvaloniaApp().StartWithClassicDesktopLifetime(args);
        }
        catch (Exception exception)
        {
            Log.Fatal(exception, "Application terminated unexpectedly");
            return 1;
        }
        finally { Log.CloseAndFlush(); }
    }

    public static AppBuilder BuildAvaloniaApp() => AppBuilder.Configure<App>()
        .UsePlatformDetect().WithInterFont().LogToTrace();
}
