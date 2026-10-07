using Avalonia.Controls;
using Serilog;
using WirelessSecurityAnalyzer.App.ViewModels;

namespace WirelessSecurityAnalyzer.App.Views;

public partial class MainWindow : Window
{
    private bool _shutdownStarted;
    private bool _shutdownCompleted;
    public MainWindow()
    {
        InitializeComponent();
        Opened += async (_, _) =>
        {
            if (DataContext is MainWindowViewModel viewModel)
                await viewModel.InitializeCommand.ExecuteAsync(null);
        };
        Closing += async (_, e) =>
        {
            if (_shutdownCompleted || DataContext is not MainWindowViewModel viewModel) return;
            e.Cancel = true;
            if (_shutdownStarted) return;
            _shutdownStarted = true;
            try { await viewModel.StopAsync(); }
            catch (Exception exception) { Log.Error(exception, "Application shutdown failed"); }
            finally
            {
                _shutdownCompleted = true;
                Close();
            }
        };
    }
}
