using System.ComponentModel;
using CommunityToolkit.Mvvm.Input;
using WirelessSecurityAnalyzer.App.Services;

namespace WirelessSecurityAnalyzer.App.ViewModels;

public sealed partial class DashboardViewModel : ViewModelBase, IDisposable
{
    private DevicesViewModel? _devices;
    private NetworkAuditViewModel? _audit;
    private readonly LoggingSettingsService? _logging;
    public DashboardViewModel(AccessPointsViewModel accessPoints, SignalViewModel signal,
        NetworkSessionViewModel? session = null, LoggingSettingsService? logging = null)
    {
        AccessPoints = accessPoints; Signal = signal; Session = session; _logging = logging;
        accessPoints.PropertyChanged += Changed;
        if (session is not null) session.PropertyChanged += Changed;
    }
    public AccessPointsViewModel AccessPoints { get; }
    public SignalViewModel Signal { get; }
    public NetworkSessionViewModel? Session { get; private set; }
    public event Action<string>? NavigationRequested;
    public string NetworkStatus => Session?.IsReady == true ? Session.Summary :
        _devices?.IsLoading == true ? "Определяем доступные интерфейсы…" : "Для поиска устройств выберите интерфейс Ethernet или Wi-Fi.";
    public string DiscoveryStatus => _devices?.IsBusy == true ? "Поиск устройств выполняется" : _devices?.IsMonitoring == true ? "Мониторинг устройств активен" :
        _devices?.HasDiscoveryResults == true ? $"Известно устройств: {_devices.KnownCount} · {_devices.LastScanText}" : "Поиск устройств ещё не выполнялся";
    public string AuditStatus => _audit?.HasAudit == true ? _audit.CompactStatus : "Поиск служб ещё не выполнялся";
    public string NextActionText => Session is { IsConnecting: true } or { IsObtainingAddress: true } ? "Ожидание подключения…" :
        _audit?.IsAuditing == true ? "Показать аудит" : _devices is { IsBusy: true } or { IsMonitoring: true }
        ? "Показать устройства" : AccessPoints.IsBusy ? "Показать эфир" : Session?.IsReady == true
            ? _devices?.HasDiscoveryResults == true ? "Найти серверы" : "Найти устройства"
            : AccessPoints.HasAdapter && _devices?.SelectedNetwork is null ? "Сканировать сети" : "Выбрать интерфейс";
    public string NextStep => Session is { IsConnecting: true } or { IsObtainingAddress: true } ? Session.Status :
        _audit?.IsAuditing == true ? "Результаты появляются по мере проверки. Остановить поиск можно в разделе аудита." :
        _devices is { IsBusy: true } or { IsMonitoring: true } ? "Устройства появляются сразу; имена и производители уточняются отдельно." :
        Session?.IsReady == true ? _devices?.HasDiscoveryResults == true ? "Проверьте найденные узлы на наличие SMB, FTP и веб-служб." :
            "Найдите узлы выбранной подсети. Подключение именно через Wi-Fi для этого не требуется." :
            "Можно подключиться к Wi-Fi в «Эфире» или выбрать уже подключённый интерфейс в «Устройствах».";
    public bool HasRecentAir => AccessPoints.HasSnapshot;
    public string RecentAir => $"{AccessPoints.ResultCaption} · {AccessPoints.LastScanText}";
    public string LogWarning => _logging?.WarningMessage ?? "";
    public bool HasLogWarning => LogWarning.Length > 0;
    public void AttachWorkflow(DevicesViewModel devices, NetworkAuditViewModel? audit, NetworkSessionViewModel? session)
    {
        if (_devices is not null) _devices.PropertyChanged -= Changed;
        if (_audit is not null) _audit.PropertyChanged -= Changed;
        if (Session is not null) Session.PropertyChanged -= Changed;
        _devices = devices; _audit = audit; Session = session ?? Session;
        devices.PropertyChanged += Changed;
        if (audit is not null) audit.PropertyChanged += Changed;
        if (Session is not null) Session.PropertyChanged += Changed;
        Changed(this, new(""));
    }
    private bool CanContinue() => Session?.IsConnecting != true && Session?.IsObtainingAddress != true && _devices?.IsLoading != true;
    [RelayCommand(CanExecute = nameof(CanContinue), AllowConcurrentExecutions = true)]
    private async Task ContinueAsync()
    {
        if (_audit?.IsAuditing == true) { Navigate("Сетевой аудит"); return; }
        if (_devices is { IsBusy: true } or { IsMonitoring: true }) { Navigate("Устройства"); return; }
        if (AccessPoints.IsBusy) { Navigate("Эфир"); return; }
        if (Session?.IsReady == true && _devices is not null)
        {
            if (_devices.HasDiscoveryResults && _audit is not null)
            { Navigate("Сетевой аудит"); if (_audit.PrimaryActionCommand.CanExecute(null)) await _audit.PrimaryActionCommand.ExecuteAsync(null); }
            else
            { Navigate("Устройства"); if (_devices.ScanCommand.CanExecute(null)) await _devices.ScanCommand.ExecuteAsync(null); }
        }
        else if (AccessPoints.HasAdapter && _devices?.SelectedNetwork is null)
        { Navigate("Эфир"); if (AccessPoints.ScanCommand.CanExecute(null)) await AccessPoints.ScanCommand.ExecuteAsync(null); }
        else Navigate("Устройства");
    }
    [RelayCommand]
    private void Navigate(string page) => NavigationRequested?.Invoke(page);
    private void Changed(object? sender, PropertyChangedEventArgs e)
    { OnPropertyChanged(string.Empty); ContinueCommand.NotifyCanExecuteChanged(); }
    public void Dispose()
    {
        AccessPoints.PropertyChanged -= Changed;
        if (Session is not null) Session.PropertyChanged -= Changed;
        if (_devices is not null) _devices.PropertyChanged -= Changed;
        if (_audit is not null) _audit.PropertyChanged -= Changed;
    }
}
