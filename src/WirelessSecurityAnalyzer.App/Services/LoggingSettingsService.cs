using System.Text.Json;
using Serilog;

namespace WirelessSecurityAnalyzer.App.Services;

/// <summary>User preferences are independent of the read-only application directory.</summary>
public sealed class LoggingSettingsService
{
    private static readonly JsonSerializerOptions Json = new() { PropertyNamingPolicy = JsonNamingPolicy.CamelCase, WriteIndented = true };
    private readonly string _preferencesPath;
    private bool _preferenceSaved;
    public LoggingSettingsService(string? applicationDataDirectory = null)
    {
        var local = Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData, Environment.SpecialFolderOption.DoNotVerify);
        var data = applicationDataDirectory ?? Path.Combine(string.IsNullOrEmpty(local) ? Path.GetTempPath() : local, "WirelessSecurityAnalyzer");
        DefaultDirectory = Path.GetFullPath(Path.Combine(data, "Logs"));
        _preferencesPath = Path.GetFullPath(Path.Combine(data, "settings.json"));
        ActiveDirectory = DefaultDirectory;
    }
    public string DefaultDirectory { get; }
    public string ActiveDirectory { get; private set; }
    public string? ConfiguredDirectory { get; private set; }
    public string RequestedDirectory => ConfiguredDirectory ?? DefaultDirectory;
    public string WarningMessage { get; private set; } = "";
    public bool UsesDifferentDirectory => !string.Equals(RequestedDirectory, ActiveDirectory,
        OperatingSystem.IsWindows() ? StringComparison.OrdinalIgnoreCase : StringComparison.Ordinal);
    public bool RestartRequired => _preferenceSaved && UsesDifferentDirectory;

    public ILogger InitializeLogger()
    {
        ConfiguredDirectory = null; WarningMessage = ""; _preferenceSaved = false;
        try
        {
            if (File.Exists(_preferencesPath))
            {
                if (new FileInfo(_preferencesPath).Length > 65536) throw new InvalidDataException("Oversized preferences.");
                var preferences = JsonSerializer.Deserialize<Preferences>(File.ReadAllText(_preferencesPath), Json);
                if (preferences?.SchemaVersion != 1) throw new InvalidDataException("Unknown preferences format.");
                ConfiguredDirectory = Normalize(preferences.Directory);
            }
        }
        catch (Exception ex) when (IsFileError(ex) || ex is JsonException)
        { WarningMessage = "Не удалось прочитать настройки журналов. Используется папка по умолчанию."; }

        var fallback = Path.Combine(Path.GetTempPath(), "WirelessSecurityAnalyzer-" + Environment.UserName, "Logs");
        foreach (var directory in new[] { RequestedDirectory, DefaultDirectory, fallback }.Distinct())
        {
            try
            {
                Validate(directory);
                var logger = new LoggerConfiguration().MinimumLevel.Information()
                    .WriteTo.File(Path.Combine(directory, "app-.log"), rollingInterval: RollingInterval.Day,
                        retainedFileCountLimit: 14, shared: true).CreateLogger();
                ActiveDirectory = directory;
                if (!string.Equals(directory, RequestedDirectory, StringComparison.Ordinal))
                    WarningMessage = "Выбранная папка журналов недоступна. Журнал записывается в: " + directory + ". Измените путь в настройках.";
                if (WarningMessage.Length > 0) logger.Warning("Logging settings: {Warning}", WarningMessage);
                return logger;
            }
            catch (Exception ex) when (IsFileError(ex))
            { WarningMessage = "Не удалось открыть папку журналов. Выберите доступный каталог в настройках."; }
        }
        ActiveDirectory = "";
        WarningMessage = "Журнал недоступен даже во временной папке. Выберите доступный каталог в настройках; диагностика файлов сейчас не записывается.";
        System.Diagnostics.Trace.WriteLine(WarningMessage);
        return new LoggerConfiguration().CreateLogger();
    }

    public void SaveDirectory(string? value)
    {
        var directory = Normalize(value);
        Validate(directory ?? DefaultDirectory);
        Directory.CreateDirectory(Path.GetDirectoryName(_preferencesPath)!);
        var temporary = _preferencesPath + "." + Guid.NewGuid().ToString("N") + ".tmp";
        try
        {
            File.WriteAllText(temporary, JsonSerializer.Serialize(new Preferences(directory), Json));
            File.Move(temporary, _preferencesPath, overwrite: true);
            ConfiguredDirectory = directory;
            _preferenceSaved = true;
            WarningMessage = "";
        }
        finally { if (File.Exists(temporary)) File.Delete(temporary); }
    }

    private static string? Normalize(string? value)
    {
        if (string.IsNullOrWhiteSpace(value)) return null;
        if (!Path.IsPathFullyQualified(value.Trim())) throw new ArgumentException("Укажите полный путь к папке журналов.");
        return Path.TrimEndingDirectorySeparator(Path.GetFullPath(value.Trim()));
    }
    private static void Validate(string directory)
    {
        Directory.CreateDirectory(directory);
        var probe = Path.Combine(directory, ".wsa-write-" + Guid.NewGuid().ToString("N"));
        using var stream = new FileStream(probe, FileMode.CreateNew, FileAccess.Write, FileShare.None, 1, FileOptions.DeleteOnClose);
        stream.WriteByte(0);
        stream.Flush(flushToDisk: true);
    }
    private static bool IsFileError(Exception ex) => ex is IOException or UnauthorizedAccessException or ArgumentException or NotSupportedException or System.Security.SecurityException;
    private sealed record Preferences(string? Directory, int SchemaVersion = 1);
}
