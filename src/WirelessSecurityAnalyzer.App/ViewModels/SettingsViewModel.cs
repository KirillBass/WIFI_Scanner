namespace WirelessSecurityAnalyzer.App.ViewModels;

public sealed class SettingsViewModel(AccessPointsViewModel accessPoints) : ViewModelBase
{
    public AccessPointsViewModel AccessPoints { get; } = accessPoints;
    public string LogsDirectory => Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
        "WirelessSecurityAnalyzer", "Logs");
}
