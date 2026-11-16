using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;
using Serilog;
using WirelessSecurityAnalyzer.Core.Common;
using WirelessSecurityAnalyzer.Core.Interfaces;

namespace WirelessSecurityAnalyzer.App.ViewModels;

/// <summary>Shared Wi-Fi error state and access to Windows location permissions.</summary>
public abstract partial class WifiViewModelBase(ISystemSettingsService settings, ILogger logger) : ViewModelBase
{
    protected ILogger Logger { get; } = logger;
    [ObservableProperty] private string _statusText = "Сначала выполните сканирование Wi-Fi эфира.";
    [ObservableProperty] private string _errorMessage = string.Empty;
    [ObservableProperty] private bool _hasError;
    [ObservableProperty] private bool _isLocationPermissionRequired;

    protected abstract string UnexpectedErrorMessage { get; }
    protected abstract string FailureStatus { get; }

    protected void SetError(Exception? exception)
    {
        HasError = exception is not null;
        IsLocationPermissionRequired = exception is WifiException { Kind: WifiErrorKind.AccessDenied };
        ErrorMessage = exception switch
        {
            null => string.Empty,
            WifiException wifi => WifiErrorPresenter.GetMessage(wifi),
            _ => UnexpectedErrorMessage
        };
    }

    protected virtual void ShowError(Exception exception)
    {
        SetError(exception);
        StatusText = FailureStatus;
    }

    [RelayCommand]
    private void OpenLocationSettings()
    {
        try { settings.OpenLocationSettings(); }
        catch (Exception exception)
        {
            Logger.Error(exception, "Opening location settings failed");
            SetError(exception);
            StatusText = "Не удалось открыть параметры Windows.";
        }
    }
}
