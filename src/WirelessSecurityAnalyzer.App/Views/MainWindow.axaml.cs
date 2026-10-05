using Avalonia.Controls;
using WirelessSecurityAnalyzer.App.ViewModels;

namespace WirelessSecurityAnalyzer.App.Views;

public partial class MainWindow : Window
{
    public MainWindow()
    {
        InitializeComponent();
        Opened += async (_, _) =>
        {
            if (DataContext is MainWindowViewModel viewModel)
                await viewModel.InitializeCommand.ExecuteAsync(null);
        };
    }
}
