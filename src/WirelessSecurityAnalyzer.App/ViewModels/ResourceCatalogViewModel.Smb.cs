using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;
using WirelessSecurityAnalyzer.Core.NetworkAudit;

namespace WirelessSecurityAnalyzer.App.ViewModels;

public sealed record SmbShareRow(SmbShare Share, ResourceAccess? Access = null)
{
    public string Name => Share.Name;
    public string UncPath => Share.UncPath;
    public bool IsAvailable => Access == ResourceAccess.Granted;
    public string AccessText => Access switch
    {
        ResourceAccess.Granted => "Доступен",
        ResourceAccess.AuthenticationRequired => "Требуется авторизация",
        ResourceAccess.Denied => "Доступ запрещён",
        ResourceAccess.Unsupported => "Не поддерживается",
        ResourceAccess.Unavailable => "Не удалось проверить",
        _ => "Доступ не проверен"
    };
}

public sealed partial class ResourceCatalogViewModel
{
    private sealed record SmbPanelListing(SmbShareListing Result, IReadOnlyList<SmbShareRow> Rows, bool UsedNamedAccount)
    {
        public bool HasList => Result.State == CatalogState.Complete || Rows.Count > 0;
        public string Summary => Result.State switch
        {
            CatalogState.Complete when Rows.Count > 0 => $"Общих папок: {Rows.Count:N0}",
            CatalogState.Complete => "Общих папок нет",
            CatalogState.Partial => $"Общих папок: {Rows.Count:N0} · список неполный",
            _ => Result.Access switch
            {
                ResourceAccess.AuthenticationRequired => "Требуется авторизация",
                ResourceAccess.Denied => "Доступ запрещён",
                ResourceAccess.Unsupported => "Перечисление недоступно",
                _ => "Ошибка перечисления"
            }
        };
    }

    private readonly Dictionary<(Guid Audit, string Address, int Port), SmbPanelListing> _shareListings = [];
    private (Guid Audit, string Address, int Port)? _smbLoadingEndpoint;
    private SmbPanelListing? _smbListing;
    private SmbShare? _openedSmbShare;

    public bool ShowsSmbShares => IsExpanded && IsSmb && _openedSmbShare is null;
    public bool ShowsDirectory => IsExpanded && (IsFtp || _openedSmbShare is not null);
    public bool ShowsCatalogStatus => IsFtp || _openedSmbShare is not null;
    public bool CanListSmbShares => ShowsSmbShares && !IsWorking && _endpoint?.Port == 445 &&
        _network is not null && smbShares is not null;
    public bool CanChooseSmbShare => ShowsSmbShares && !IsWorking && !IsSmbAccountEditorOpen && _smbListing?.HasList == true;
    public IReadOnlyList<SmbShareRow> SmbRows => _smbListing?.Rows ?? [];
    public string SmbShareHeading => _smbListing?.HasList == true
        ? $"Обнаружено общих ресурсов: {SmbRows.Count:N0}" : "Общие папки";
    public string SmbShareCounts => _smbListing?.HasList == true
        ? $"Обнаружено ресурсов: {SmbRows.Count:N0} · Доступно: {SmbRows.Count(row => row.Access == ResourceAccess.Granted):N0}" : "";
    public string SmbListActionText => IsSmbAccountEditorOpen ? "Запросить список" : "Обновить список";
    public bool CanEditSmbAccount => IsSmb && _endpoint?.Port == 445 && smbShares is not null;

    [ObservableProperty]
    [NotifyPropertyChangedFor(nameof(CanChooseSmbShare), nameof(SmbListActionText))]
    private bool _isSmbAccountEditorOpen;

    [ObservableProperty] private string _smbShareMessage = "";
    [ObservableProperty] private SmbShareRow? _selectedSmbShare;

    private string SmbSummary(AuditRow row)
    {
        var key = Key(row);
        if (_smbLoadingEndpoint == key) return "Обнаружение ресурсов…";
        if (row.Port != 445) return "Перечисление доступно на TCP 445";
        if (_endpoint is not null && Key(_endpoint) == key) return _smbListing?.Summary ?? "";
        return _shareListings.GetValueOrDefault(key)?.Summary ?? "";
    }

    private void RestoreSmbListing(bool showLogin = false)
    {
        _smbListing = IsSmb ? _shareListings.GetValueOrDefault(Key(_endpoint!)) : null;
        // A cached list from a different account is only a list of names until the new account is applied.
        var needsAccount = _smbListing?.UsedNamedAccount == true || HasNamedLogin;
        if (needsAccount && _smbListing is { } cached)
            _smbListing = cached with { Rows = cached.Rows.Select(row => row with { Access = null }).ToArray() };
        IsSmbAccountEditorOpen = CanEditSmbAccount && (showLogin || needsAccount || _smbListing?.HasList != true);
        SmbShareMessage = _smbListing?.Result.Message ?? (_endpoint switch
        {
            { HasSmbService: true, Port: not 445 } => "Перечисление общих папок через клиент Windows доступно на TCP 445.",
            { HasSmbService: true } when smbShares is null => "Сервис перечисления общих папок недоступен.",
            { HasSmbService: true } => "Выберите учётную запись и запросите список для этого сервера.",
            _ => ""
        });
        if (needsAccount && _smbListing?.HasList == true)
            SmbShareMessage = "Список сохранён. Запросите его с выбранной учётной записью, чтобы открыть папку.";
        NotifySmbPanel();
    }

    private void NotifySmbPanel()
    {
        foreach (var name in new[]
        {
            nameof(ShowsSmbShares), nameof(ShowsDirectory), nameof(ShowsCatalogStatus),
            nameof(CanListSmbShares), nameof(CanChooseSmbShare), nameof(CanEditSmbAccount), nameof(SmbShareHeading),
            nameof(SmbShareCounts), nameof(SmbRows)
        })
            OnPropertyChanged(name);
    }

    [RelayCommand]
    private void EditSmbAccount()
    {
        if (!CanListSmbShares) return;
        IsSmbAccountEditorOpen = true;
        SmbShareMessage = "Выберите учётную запись и запросите список для этого сервера.";
    }

    [RelayCommand]
    private async Task LoadSmbSharesAsync()
    {
        if (!CanListSmbShares || _endpoint is not { } endpoint || _network is not { } network || smbShares is null) return;
        if (LoginMode is not (0 or 1) || HasNamedLogin && string.IsNullOrWhiteSpace(UserName))
        {
            SmbShareMessage = "Укажите учётную запись для запроса списка.";
            return;
        }

        var credential = CreateCredential();
        var generation = _generation;
        var key = Key(endpoint);
        using var operation = new CancellationTokenSource();
        _operation = operation;
        _smbLoadingEndpoint = key;
        IsWorking = true;
        SmbShareMessage = "Получаем список общих папок…";
        SummaryChanged?.Invoke();
        try
        {
            var result = await ListSmbSharesAsync();
            operation.Token.ThrowIfCancellationRequested();
            if (generation != _generation) return;
            var listing = new SmbPanelListing(result, result.Shares.Select(share => new SmbShareRow(share)).ToArray(),
                UsedNamedAccount: credential is not null);
            _smbListing = listing;
            _shareListings[key] = listing;
            IsSmbAccountEditorOpen = !listing.HasList;
            SmbShareMessage = result.Message;
        }
        catch (OperationCanceledException) when (operation.IsCancellationRequested)
        {
            if (generation == _generation) SmbShareMessage = "Получение списка отменено.";
        }
        finally
        {
            _smbLoadingEndpoint = null;
            _operation = null;
            IsWorking = false;
            if (generation == _generation) NotifySmbPanel();
            SummaryChanged?.Invoke();
        }

        async Task<SmbShareListing> ListSmbSharesAsync()
        {
            try
            {
                if (networks is not null && !await networks.IsCurrentAsync(network, operation.Token))
                    return new([], ResourceAccess.Unavailable, CatalogState.Failed, "Выбранный сетевой интерфейс изменился.");
                operation.Token.ThrowIfCancellationRequested();
                return await smbShares.ListAsync(network, endpoint, credential, operation.Token);
            }
            catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or InvalidOperationException or ArgumentException or
                System.Net.NetworkInformation.NetworkInformationException or PlatformNotSupportedException or System.ComponentModel.Win32Exception)
            {
                return new([], ResourceAccess.Unavailable, CatalogState.Failed, "Не удалось получить список общих папок.");
            }
        }
    }

    partial void OnSelectedSmbShareChanged(SmbShareRow? value)
    {
        if (value is null || !CanChooseSmbShare || !SmbRows.Contains(value)) return;
        _openedSmbShare = value.Share;
        CurrentPath = value.UncPath;
        OnPropertyChanged(nameof(CanRead));
        NotifySmbPanel();
        _ = ReadRootCommand.ExecuteAsync(null);
    }

    [RelayCommand]
    private void BackToSmbShares()
    {
        if (!IsSmb || IsWorking) return;
        ResetDirectory();
    }

    private void SetSmbShareAccess(AuditRow endpoint, SmbShare share, ResourceAccess access)
    {
        if (_smbListing is not { } listing) return;
        var updated = listing with
        {
            Rows = listing.Rows.Select(row => row.Share == share ? row with { Access = access } : row).ToArray()
        };
        _smbListing = updated;
        _shareListings[Key(endpoint)] = updated;
        OnPropertyChanged(nameof(SmbShareCounts));
        OnPropertyChanged(nameof(SmbRows));
    }
}
