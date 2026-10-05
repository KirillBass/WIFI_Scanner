namespace WirelessSecurityAnalyzer.App.ViewModels;

public sealed class DashboardViewModel(AccessPointsViewModel accessPoints) : ViewModelBase
{
    public AccessPointsViewModel AccessPoints { get; } = accessPoints;
}
