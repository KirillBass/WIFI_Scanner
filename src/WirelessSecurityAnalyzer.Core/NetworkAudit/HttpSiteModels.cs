using System.Net;
using WirelessSecurityAnalyzer.Core.Models;

namespace WirelessSecurityAnalyzer.Core.NetworkAudit;

public enum HttpSiteState { NotChecked, Checking, HttpConfirmed, SiteFound, AccessRestricted, StartPageNotFound, ConnectionError }
public sealed record HttpPage(Uri Url, int StatusCode, string Title, string Source);
public sealed record HttpSiteResult(Guid SessionId, Guid AuditId, IPAddress Address, int Port, Uri Origin,
    string AssumedProtocol, string OriginalService, string DiscoverySource)
{
    public HttpSiteState State { get; init; } = HttpSiteState.NotChecked;
    public Uri? StartUrl { get; init; }
    public int? StatusCode { get; init; }
    public string ContentType { get; init; } = "";
    public string Title { get; init; } = "";
    public string Server { get; init; } = "";
    public string Evidence { get; init; } = "";
    public bool HttpConfirmed { get; init; }
    public bool IsPartial { get; init; }
    public int RequestsChecked { get; init; }
    public IReadOnlyList<HttpPage> Pages { get; init; } = [];
    public IReadOnlyList<string> ExternalLinks { get; init; } = [];
    public string Message { get; init; } = "";
    public string StateText => State switch
    {
        HttpSiteState.Checking => "Проверяются HTTP-страницы", HttpSiteState.HttpConfirmed => "HTTP подтверждён",
        HttpSiteState.SiteFound => "Сайт найден", HttpSiteState.AccessRestricted => "Доступ ограничен",
        HttpSiteState.StartPageNotFound => "Стартовая страница не найдена", HttpSiteState.ConnectionError => "Ошибка соединения",
        _ => "Проверка не проводилась"
    };
    public string Url => (StartUrl ?? Origin).AbsoluteUri;
    public string Summary => $"{StateText} · {Url} · страниц: {Pages.Count}";
    public string Details => $"{StateText}{(IsPartial ? " · результат неполный" : "")}\n{Url}\nHTTP стартовой страницы: {StatusCode?.ToString() ?? "не запрашивалась / ответ не получен"} · {ContentType}\n{Title}\n{Message}\n{Evidence}\nЗапросов: {RequestsChecked}; HTML-страниц: {Pages.Count}\nИсточник: {DiscoverySource}; исходная служба: {OriginalService}\n" +
        (ExternalLinks.Count == 0 ? "" : "Ссылки за пределами обхода (не запрашивались):\n" + string.Join("\n", ExternalLinks));
}

public sealed class HttpSiteDiscoveryOptions
{
    public TimeSpan RequestTimeout { get; init; } = TimeSpan.FromSeconds(5);
    public TimeSpan SiteTimeout { get; init; } = TimeSpan.FromSeconds(45);
    public int MaxHtmlBytes { get; init; } = 1024 * 1024;
    public int MaxPages { get; init; } = 30;
    public int MaxDepth { get; init; } = 2;
    public int RequestsPerSite { get; init; } = 60;
    public int ConcurrentRequestsPerSite { get; init; } = 2;
    public int ConcurrentCandidates { get; init; } = 4;
    public int MaxRedirects { get; init; } = 5;
    public int MaxOriginsPerEndpoint { get; init; } = 5;
    public void Validate()
    {
        if (RequestTimeout <= TimeSpan.Zero || SiteTimeout < RequestTimeout || MaxHtmlBytes is < 1024 or > 1024 * 1024 ||
            MaxPages is < 1 or > 30 || MaxDepth is < 0 or > 2 || RequestsPerSite is < 1 or > 60 ||
            ConcurrentRequestsPerSite is < 1 or > 2 || ConcurrentCandidates is < 1 or > 4 || MaxRedirects is < 0 or > 5 ||
            MaxOriginsPerEndpoint is < 1 or > 5) throw new ArgumentException("Некорректные ограничения поиска HTTP-страниц.");
    }
}

public interface IHttpSiteDiscovery
{
    Task DiscoverAsync(LocalNetworkInfo network, AuditRow candidate, Action<IReadOnlyList<HttpSiteResult>> publish, CancellationToken cancellationToken);
}
