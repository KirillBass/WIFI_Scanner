namespace WirelessSecurityAnalyzer.App.Services;

/// <summary>Only preferences are persisted; network results and credentials are never stored here.</summary>
public sealed record UserPreferences
{
    public static IReadOnlyList<string> Pages { get; } = ["Эфир", "Каналы", "Сигнал", "Устройства", "Сетевой аудит", "Настройки"];
    public bool RememberInterface { get; init; }
    public string? LastInterfaceId { get; init; }
    public string StartupPage { get; init; } = "Устройства";
    public bool IncludeLocal { get; init; } = true;
    public bool CompactRows { get; init; }

    public UserPreferences Normalize() => this with
    {
        StartupPage = Pages.Contains(StartupPage) ? StartupPage : "Устройства",
        LastInterfaceId = RememberInterface && LastInterfaceId is { Length: > 0 and <= 512 } ? LastInterfaceId : null
    };
}
