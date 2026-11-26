using System.Collections.ObjectModel;
using System.Net;
using Avalonia.Threading;
using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;
using WirelessSecurityAnalyzer.Core.Interfaces;
using WirelessSecurityAnalyzer.Core.Models;
using WirelessSecurityAnalyzer.Core.NetworkAudit;

namespace WirelessSecurityAnalyzer.App.ViewModels;

public sealed partial class ResourceCatalogViewModel(IEnumerable<IResourceCatalogReader> readers, ILocalNetworkService? networks,
    ISmbShareEnumerator? smbShares = null) : ViewModelBase
{
    private readonly Dictionary<(Guid Audit, string Address, int Port), string> _ftpRootSummaries = [];
    private AuditRow? _endpoint;
    private LocalNetworkInfo? _network;
    private CancellationTokenSource? _operation;
    private long _generation;
    private string[] _folders = [];
    private string _root = "";

    public event Action? SummaryChanged;
    public ObservableCollection<ResourceEntry> Entries { get; } = [];
    public bool IsSmb => _endpoint?.HasSmbService == true;
    public bool IsFtp => _endpoint?.Protocol == "FTP";
    public bool ShowsFtpStart => IsExpanded && IsFtp && !HasOpenedFtpDirectory;
    public string FtpRootAddress => _endpoint is { Protocol: "FTP" } ftp ? $"ftp://{ftp.Address}:{ftp.Port}/" : "";
    public bool ShowsCatalogStatus => HasOpenedFtpDirectory || _openedSmbShare is not null;
    public bool ShowsDirectory => IsExpanded && ShowsCatalogStatus;
    public IReadOnlyList<string> LoginModes { get; } = ["Анонимный доступ", "Учётная запись"];
    public IReadOnlyList<string> SmbLoginModes { get; } = ["Текущая учётная запись", "Другая учётная запись"];
    public bool HasNamedLogin => LoginMode == 1;
    public bool NeedsPlaintextConsent => IsFtp && HasNamedLogin;
    public bool CanOpenFolder => !IsWorking && SelectedEntry?.Kind == ResourceEntryKind.Folder;
    public bool CanGoUp => !IsWorking && _folders.Length > 0;
    public bool CanRead => !IsWorking && _endpoint is not null && _network is not null && (!IsSmb || _openedSmbShare is not null);

    [ObservableProperty, NotifyPropertyChangedFor(nameof(ShowsFtpStart))] private bool _isExpanded;
    [ObservableProperty, NotifyPropertyChangedFor(nameof(ShowsFtpStart), nameof(ShowsCatalogStatus), nameof(ShowsDirectory))]
    private bool _hasOpenedFtpDirectory;
    [ObservableProperty, NotifyPropertyChangedFor(nameof(HasNamedLogin), nameof(NeedsPlaintextConsent))]
    private int _loginMode;
    [ObservableProperty] private string _userName = "";
    [ObservableProperty] private string _password = "";
    [ObservableProperty] private bool _allowPlaintext;
    [ObservableProperty, NotifyPropertyChangedFor(nameof(CanOpenFolder), nameof(CanGoUp), nameof(CanRead),
        nameof(CanListSmbShares), nameof(CanChooseSmbShare))]
    private bool _isWorking;
    [ObservableProperty, NotifyPropertyChangedFor(nameof(CanOpenFolder))]
    private ResourceEntry? _selectedEntry;
    [ObservableProperty] private string _currentPath = "";
    [ObservableProperty] private string _status = "";
    [ObservableProperty] private string _counts = "";

    partial void OnLoginModeChanged(int value)
    {
        UserName = Password = "";
        AllowPlaintext = false;
        if (ShowsSmbShares) RestoreSmbListing(showLogin: true);
    }

    partial void OnIsExpandedChanged(bool value)
    {
        NotifySmbPanel();
        if (value) return;
        Password = "";
        AllowPlaintext = false;
        _operation?.Cancel();
        if (IsSmb && HasNamedLogin)
        {
            _generation++;
            ResetDirectory();
            LoginMode = 0;
            RestoreSmbListing();
        }
    }

    private static (Guid, string, int) Key(AuditRow row) => (row.AuditId, row.Address, row.Port);
    public string Summary(AuditRow row) => row.HasSmbService
        ? SmbSummary(row)
        : _ftpRootSummaries.GetValueOrDefault(Key(row)) ?? "Каталог не открыт";

    public void SetScope(Guid auditId)
    {
        foreach (var key in _ftpRootSummaries.Keys.Where(key => key.Audit != auditId).ToArray())
            _ftpRootSummaries.Remove(key);
        foreach (var key in _shareListings.Keys.Where(key => key.Audit != auditId).ToArray())
            _shareListings.Remove(key);
    }

    public void Select(AuditRow? row, LocalNetworkInfo? network)
    {
        var endpoint = row is { HasFileService: true } && network is not null ? row : null;
        if (_endpoint is not null && endpoint is not null && Key(_endpoint) == Key(endpoint) &&
            _endpoint.Protocol == endpoint.Protocol && _network?.HasSameContext(network!) == true)
            return;
        if (_endpoint is null && endpoint is null) return;

        _generation++;
        _operation?.Cancel();
        _endpoint = endpoint;
        _network = network;
        _smbListing = null;
        ResetDirectory();
        IsExpanded = IsSmb || IsFtp;
        LoginMode = 0;
        UserName = Password = "";
        if (IsFtp) AllowPlaintext = false;
        OnPropertyChanged(nameof(IsSmb));
        OnPropertyChanged(nameof(IsFtp));
        OnPropertyChanged(nameof(NeedsPlaintextConsent));
        OnPropertyChanged(nameof(CanGoUp));
        OnPropertyChanged(nameof(CanRead));

        RestoreSmbListing();
        Status = IsFtp ? "Доступ не проверен" : "";
        OnPropertyChanged(nameof(FtpRootAddress));
        OnPropertyChanged(nameof(ShowsFtpStart));
    }

    public void Stop() => _operation?.Cancel();

    [RelayCommand] private void CancelCatalogue()
    {
        if (_operation is null) return;
        _operation.Cancel();
        if (ShowsSmbShares) SmbShareMessage = "Отмена запрошена. Ожидается завершение вызова Windows.";
        else Status = IsSmb ? "Отмена запрошена. Ожидается завершение вызова Windows." : "Отмена запрошена.";
    }

    [RelayCommand] private Task ReadRootAsync() => ReadAsync([]);
    [RelayCommand] private Task RefreshCatalogAsync() => ReadAsync(_folders);
    [RelayCommand] private Task OpenFolderAsync() => CanOpenFolder && SelectedEntry is { } entry
        ? ReadAsync([.. _folders, entry.Name]) : Task.CompletedTask;
    [RelayCommand] private Task ParentFolderAsync() => CanGoUp ? ReadAsync(_folders[..^1]) : Task.CompletedTask;

    private async Task ReadAsync(string[] folders)
    {
        if (!CanRead || _endpoint is not { } endpoint || _network is not { } network) return;
        var reader = readers.FirstOrDefault(r => r.Protocol == TargetServiceMatcher.Family(endpoint.Protocol));
        if (reader is null) return;
        var isFtp = endpoint.Protocol == "FTP";
        if (NeedsPlaintextConsent && !AllowPlaintext)
        {
            Status = "Подтвердите использование обычного FTP для этой учётной записи.";
            return;
        }
        if (HasNamedLogin && string.IsNullOrWhiteSpace(UserName))
        {
            Status = "Укажите имя пользователя.";
            return;
        }
        var generation = _generation;
        var smbShare = _openedSmbShare;
        using var operation = new CancellationTokenSource();
        _operation = operation;
        IsWorking = true;
        _folders = folders;
        if (folders.Length == 0) _root = "";
        var credential = CreateCredential();
        var root = smbShare?.UncPath ?? _root;
        var buffer = new List<ResourceEntry>();
        var known = new HashSet<string>(IsSmb ? StringComparer.OrdinalIgnoreCase : StringComparer.Ordinal);
        var folderCount = 0;
        var fileCount = 0;
        var linkCount = 0;
        Entries.Clear();
        SelectedEntry = null;
        Status = "Читается список объектов…";
        Counts = "";
        void UpdateCounts() => Counts = $"Папок: {folderCount:N0} · файлов: {fileCount:N0} · ссылок: {linkCount:N0}";

        void Flush()
        {
            ResourceEntry[] batch;
            lock (buffer)
            {
                if (buffer.Count == 0) return;
                batch = buffer.ToArray();
                buffer.Clear();
            }
            if (generation != _generation) return;
            foreach (var entry in batch)
            {
                if (!known.Add(entry.RemotePath)) continue;
                Entries.Add(entry);
                switch (entry.Kind)
                {
                    case ResourceEntryKind.Folder: folderCount++; break;
                    case ResourceEntryKind.File: fileCount++; break;
                    default: linkCount++; break;
                }
            }
            UpdateCounts();
            if (isFtp) HasOpenedFtpDirectory = true;
        }

        var timer = new DispatcherTimer { Interval = TimeSpan.FromMilliseconds(120) };
        timer.Tick += (_, _) => Flush();
        timer.Start();
        string summary;
        var ftpListingComplete = false;
        try
        {
            if (networks is not null && !await networks.IsCurrentAsync(network, operation.Token))
            {
                summary = "Выбранный сетевой интерфейс изменился.";
            }
            else
            {
                operation.Token.ThrowIfCancellationRequested();
                var result = await reader.ReadAsync(network, endpoint, root, folders, credential,
                    entry => { lock (buffer) buffer.Add(entry); }, operation.Token);
                operation.Token.ThrowIfCancellationRequested();
                Flush();
                if (generation != _generation) return;
                if (result.Root.Length > 0) _root = result.Root;
                if (result.Path.Length > 0) CurrentPath = result.Path;
                if (isFtp && result is { Access: ResourceAccess.Granted, State: CatalogState.Complete })
                {
                    ftpListingComplete = true;
                    UpdateCounts();
                    HasOpenedFtpDirectory = true;
                }
                if (smbShare is not null && folders.Length == 0)
                    SetSmbShareAccess(endpoint, smbShare, result.Access);
                summary = result.State == CatalogState.Complete && Entries.Count > 0 ? Counts :
                    result.State == CatalogState.Partial ? "Неполный результат. " + result.Message : result.Message;
            }
        }
        catch (OperationCanceledException) when (operation.IsCancellationRequested)
        {
            summary = "Отменено. Полученные объекты сохранены. Результат неполный.";
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or InvalidOperationException or ArgumentException or
            System.Net.NetworkInformation.NetworkInformationException or PlatformNotSupportedException)
        {
            summary = "Не удалось завершить чтение каталога.";
        }
        finally
        {
            timer.Stop();
            Flush();
            _operation = null;
            IsWorking = false;
        }

        if (generation != _generation) return;
        Status = summary;
        if (isFtp && !ftpListingComplete && Counts.Length > 0)
            Counts = "Получено частично · " + Counts;
        if (isFtp && folders.Length == 0)
        {
            _ftpRootSummaries[Key(endpoint)] = "Корневой каталог · " + (ftpListingComplete ? Counts : summary);
            SummaryChanged?.Invoke();
        }
    }

    private NetworkCredential? CreateCredential()
    {
        if (!HasNamedLogin) return null;
        var user = UserName.Trim();
        var parts = IsSmb ? user.Split('\\', 2) : [user];
        return new(parts[^1], Password, parts.Length == 2 ? parts[0] : "");
    }

    private void ResetDirectory()
    {
        HasOpenedFtpDirectory = false;
        _openedSmbShare = null;
        SelectedSmbShare = null;
        _folders = [];
        _root = CurrentPath = Counts = Status = "";
        Entries.Clear();
        SelectedEntry = null;
        OnPropertyChanged(nameof(CanRead));
        OnPropertyChanged(nameof(CanGoUp));
        NotifySmbPanel();
    }
}
