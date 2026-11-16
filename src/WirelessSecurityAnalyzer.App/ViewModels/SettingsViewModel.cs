using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;
using Serilog;
using WirelessSecurityAnalyzer.App.Services;

namespace WirelessSecurityAnalyzer.App.ViewModels;

public sealed partial class SettingsViewModel : ViewModelBase
{
    private readonly LoggingSettingsService _logging;
    private readonly IUserFolderService _folders;
    public SettingsViewModel(AccessPointsViewModel accessPoints, LoggingSettingsService? logging = null, IUserFolderService? folders = null)
    { AccessPoints = accessPoints; _logging = logging ?? new(); _folders = folders ?? new UserFolderService(); }
    public AccessPointsViewModel AccessPoints { get; }
    public string LogsDirectory => _logging.ActiveDirectory.Length == 0 ? "Недоступна" : _logging.ActiveDirectory;
    public string SelectedDirectory => _logging.RequestedDirectory;
    public string WarningMessage => _logging.WarningMessage;
    public bool HasWarning => WarningMessage.Length > 0;
    public bool RestartRequired => _logging.RestartRequired;
    public bool UsesDifferentDirectory => _logging.UsesDifferentDirectory;
    public bool HasError => ErrorMessage.Length > 0;
    [ObservableProperty, NotifyCanExecuteChangedFor(nameof(ChangeDirectoryCommand), nameof(ResetDirectoryCommand), nameof(OpenDirectoryCommand))]
    private bool _isBusy;
    [ObservableProperty, NotifyPropertyChangedFor(nameof(HasError))] private string _errorMessage = "";
    [ObservableProperty] private string _statusText = "";
    private bool CanEdit() => !IsBusy;
    [RelayCommand(CanExecute = nameof(CanEdit))]
    private async Task ChangeDirectoryAsync()
    {
        IsBusy = true; ErrorMessage = "";
        try
        {
            var path = await _folders.PickAsync(SelectedDirectory);
            if (path is null) return;
            await Task.Run(() => _logging.SaveDirectory(path));
            Saved();
        }
        catch (Exception ex) { Failed(ex); }
        finally { IsBusy = false; }
    }
    [RelayCommand(CanExecute = nameof(CanEdit))]
    private async Task ResetDirectoryAsync()
    {
        IsBusy = true; ErrorMessage = "";
        try { await Task.Run(() => _logging.SaveDirectory(null)); Saved(); }
        catch (Exception ex) { Failed(ex); }
        finally { IsBusy = false; }
    }
    [RelayCommand(CanExecute = nameof(CanEdit))]
    private void OpenDirectory()
    {
        ErrorMessage = "";
        try
        {
            if (_logging.ActiveDirectory.Length == 0) throw new IOException("No active log directory.");
            _folders.Open(_logging.ActiveDirectory);
        }
        catch (Exception ex) { Failed(ex); }
    }
    private void Saved()
    {
        StatusText = RestartRequired ? "Путь сохранён. Изменения вступят в силу после перезапуска приложения." : "Используется выбранная папка журналов.";
        foreach (var property in new[] { nameof(LogsDirectory), nameof(SelectedDirectory), nameof(RestartRequired), nameof(UsesDifferentDirectory), nameof(WarningMessage), nameof(HasWarning) }) OnPropertyChanged(property);
    }
    private void Failed(Exception ex)
    {
        Log.Warning(ex, "Log directory preference failed");
        ErrorMessage = "Не удалось использовать папку. Проверьте путь и доступ на запись. Текущая папка журналов сохранена.";
    }
}
