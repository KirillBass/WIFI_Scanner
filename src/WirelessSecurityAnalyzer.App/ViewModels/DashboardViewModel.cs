namespace WirelessSecurityAnalyzer.App.ViewModels;

public sealed class DashboardViewModel(AccessPointsViewModel accessPoints, SignalViewModel signal) : ViewModelBase
{
    public AccessPointsViewModel AccessPoints { get; } = accessPoints;
    public SignalViewModel Signal { get; } = signal;
}
