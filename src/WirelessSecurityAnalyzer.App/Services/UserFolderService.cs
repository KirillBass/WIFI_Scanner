using System.Diagnostics;
using Avalonia;
using Avalonia.Controls.ApplicationLifetimes;
using Avalonia.Platform.Storage;

namespace WirelessSecurityAnalyzer.App.Services;

public interface IUserFolderService
{
    Task<string?> PickAsync(string currentDirectory);
    void Open(string directory);
}

public sealed class UserFolderService : IUserFolderService
{
    public async Task<string?> PickAsync(string currentDirectory)
    {
        var storage = (Application.Current?.ApplicationLifetime as IClassicDesktopStyleApplicationLifetime)?.MainWindow?.StorageProvider;
        if (storage?.CanPickFolder != true) throw new InvalidOperationException("Системный выбор папки недоступен.");
        var folders = await storage.OpenFolderPickerAsync(new FolderPickerOpenOptions
        {
            Title = "Папка журналов Wireless Security Analyzer", AllowMultiple = false,
            SuggestedStartLocation = await storage.TryGetFolderFromPathAsync(new Uri(currentDirectory))
        });
        if (folders.Count == 0) return null;
        using var folder = folders[0];
        return folder.TryGetLocalPath() ?? throw new InvalidOperationException("Выберите папку на файловой системе.");
    }
    public void Open(string directory) => Process.Start(new ProcessStartInfo(directory) { UseShellExecute = true });
}
