using Avalonia.Controls;
using Serilog;
using WirelessSecurityAnalyzer.App.ViewModels;
using WirelessSecurityAnalyzer.Core.Models;

namespace WirelessSecurityAnalyzer.App.Views;

public partial class MainWindow : Window
{
    private bool _shutdownStarted;
    private bool _shutdownCompleted;
    private WifiConnectionDialog? _connectionDialog;
    public MainWindow()
    {
        InitializeComponent();
        Opened += async (_, _) =>
        {
            if (DataContext is MainWindowViewModel viewModel)
            {
                viewModel.AccessPoints.ConnectionRequested += ShowConnectionDialog;
                await viewModel.InitializeCommand.ExecuteAsync(null);
            }
        };
        Closing += async (_, e) =>
        {
            if (_shutdownCompleted || DataContext is not MainWindowViewModel viewModel) return;
            e.Cancel = true;
            if (_shutdownStarted) return;
            _shutdownStarted = true;
            try
            {
                viewModel.AccessPoints.ConnectionRequested -= ShowConnectionDialog;
                var stopping = viewModel.StopAsync();
                if (_connectionDialog?.DataContext is WifiConnectionDialogViewModel dialog)
                { await dialog.StopAsync(); _connectionDialog.Close(); }
                await stopping;
            }
            catch (Exception exception) { Log.Error(exception, "Application shutdown failed"); }
            finally
            {
                _shutdownCompleted = true;
                Close();
            }
        };
    }

    private async void ShowConnectionDialog(WifiConnectionDialogViewModel viewModel)
    {
        if (_connectionDialog is not null || _shutdownStarted) { await viewModel.StopAsync(); return; }
        var dialog = _connectionDialog = new WifiConnectionDialog { DataContext = viewModel };
        try
        {
            var result = await dialog.ShowDialog<WifiConnectionResult?>(this);
            Log.Information("Wi-Fi dialog completed: success {Success}, state {State}, failure {Failure}",
                result?.Success, result?.State, result?.Failure);
        }
        catch (Exception exception)
        {
            Log.Error("Connection dialog unavailable: {ErrorType}", exception.GetType().Name);
            if (DataContext is MainWindowViewModel main)
                main.AccessPoints.StatusText = "Не удалось открыть окно подключения.";
        }
        finally { await viewModel.StopAsync(); _connectionDialog = null; }
    }
}
