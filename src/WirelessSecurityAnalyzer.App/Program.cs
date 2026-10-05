using Avalonia;
using Serilog;

namespace WirelessSecurityAnalyzer.App;

internal static class Program
{
    [STAThread]
    public static int Main(string[] args)
    {
        var logs = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
            "WirelessSecurityAnalyzer", "Logs");
        Log.Logger = new LoggerConfiguration().MinimumLevel.Information()
            .WriteTo.File(Path.Combine(logs, "app-.log"), rollingInterval: RollingInterval.Day,
                retainedFileCountLimit: 14, shared: true).CreateLogger();
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
