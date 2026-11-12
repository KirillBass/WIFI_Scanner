using System.Collections.Concurrent;
using System.Net;
using System.Net.Http.Headers;
using System.Net.Sockets;
using System.Text;
using AngleSharp.Html.Parser;
using WirelessSecurityAnalyzer.Core.Models;
using WirelessSecurityAnalyzer.Core.NetworkAudit;
using WirelessSecurityAnalyzer.Infrastructure.Windows.Network.Identity;

namespace WirelessSecurityAnalyzer.Infrastructure.Windows.NetworkAudit;

/// <summary>Bounded enrichment of an existing open endpoint; never enumerates addresses or ports.</summary>
public sealed class HttpSiteDiscovery : IHttpSiteDiscovery, IDisposable
{
    private readonly IHttpSiteHostResolver _names;
    private readonly HttpSiteDiscoveryOptions _options;
    private readonly Func<HttpSiteScope, HttpClient> _clients;
    private readonly Func<IReadOnlySet<IPAddress>> _localAddresses;
    private readonly SemaphoreSlim _candidates;
    public HttpSiteDiscovery(IHttpSiteHostResolver names, HttpSiteDiscoveryOptions options)
        : this(names, options, scope => CreateClient(scope, options), HttpSiteScope.LocalAddresses) { }
    internal HttpSiteDiscovery(IHttpSiteHostResolver names, HttpSiteDiscoveryOptions options,
        Func<HttpSiteScope, HttpClient> clients, Func<IReadOnlySet<IPAddress>>? localAddresses = null)
    {
        options.Validate(); _names = names; _options = options; _clients = clients;
        _localAddresses = localAddresses ?? (() => new HashSet<IPAddress>());
        _candidates = new(options.ConcurrentCandidates);
        Encoding.RegisterProvider(CodePagesEncodingProvider.Instance);
    }
    public async Task DiscoverAsync(LocalNetworkInfo network, AuditRow candidate, Action<IReadOnlyList<HttpSiteResult>> publish, CancellationToken cancellationToken)
    {
        var scope = new HttpSiteScope(network, candidate.Target.Address, candidate.Port, _names, _localAddresses(), candidate.Target.IsLocal);
        var origin = new UriBuilder("http", candidate.Target.Address.ToString(), candidate.Port).Uri;
        var initial = new HttpSiteResult(candidate.SessionId, candidate.AuditId, candidate.Target.Address, candidate.Port, origin,
            candidate.Protocol, candidate.Product, $"Открытый TCP-порт; профиль {candidate.Profile}")
            { HttpConfirmed = candidate.Protocol == "HTTP" };
        if (!scope.IsAllowedTarget)
        {
            publish([initial with { Message = "HTTP-адрес не входит в область аудита. Этот ПК проверяется по выбранному IPv4 при включённом флажке «Включить этот ПК»." }]); return;
        }
        var results = new Dictionary<string, HttpSiteResult> { [origin.AbsoluteUri] = initial with { State = HttpSiteState.Checking, Message = "Ожидает HTTP-проверки." } };
        void Update(HttpSiteResult site, Uri? previous = null)
        {
            if (previous is not null && previous != site.Origin) results.Remove(previous.AbsoluteUri);
            results[site.Origin.AbsoluteUri] = site;
            publish(Array.AsReadOnly(results.Values.ToArray()));
        }
        publish(Array.AsReadOnly(results.Values.ToArray()));
        var entered = false;
        try
        {
            await _candidates.WaitAsync(cancellationToken).ConfigureAwait(false); entered = true;
            using var client = _clients(scope);
            var crawler = new SiteCrawler(scope, client, _options);
            var origins = new List<Uri> { origin };
            foreach (var name in candidate.Target.KnownHostnames.Take(_options.MaxOriginsPerEndpoint - 1))
                if (Uri.CheckHostName(name.TrimEnd('.')) == UriHostNameType.Dns)
                {
                    var named = new UriBuilder("http", name.TrimEnd('.'), candidate.Port).Uri;
                    if (await scope.AllowAsync(named, true, cancellationToken).ConfigureAwait(false) && !origins.Contains(named)) origins.Add(named);
                }
            foreach (var start in origins)
            {
                cancellationToken.ThrowIfCancellationRequested();
                if (start != origin && results.TryGetValue(start.AbsoluteUri, out var existing) && existing.State != HttpSiteState.NotChecked) continue;
                var site = initial with { Origin = start, State = HttpSiteState.Checking, Message = "Проверяется стартовая страница." };
                Update(site);
                await crawler.CheckAsync(site, updated => Update(updated, start), cancellationToken).ConfigureAwait(false);
            }
        }
        catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
        {
            foreach (var key in results.Keys.ToArray())
            {
                var site = results[key];
                results[key] = site with { IsPartial = true, State = site.State == HttpSiteState.Checking ?
                    site.HttpConfirmed ? HttpSiteState.HttpConfirmed : HttpSiteState.NotChecked : site.State,
                    Message = "Поиск страниц остановлен. Найденные результаты сохранены." };
            }
            publish(Array.AsReadOnly(results.Values.ToArray())); throw;
        }
        finally { if (entered) _candidates.Release(); }
    }
    private static HttpClient CreateClient(HttpSiteScope scope, HttpSiteDiscoveryOptions options)
    {
        var handler = new SocketsHttpHandler
        {
            AllowAutoRedirect = false, UseProxy = false, UseCookies = false, Credentials = null,
            AutomaticDecompression = DecompressionMethods.GZip | DecompressionMethods.Deflate | DecompressionMethods.Brotli,
            ConnectTimeout = options.RequestTimeout, MaxResponseHeadersLength = 32,
            MaxConnectionsPerServer = options.ConcurrentRequestsPerSite, PooledConnectionLifetime = TimeSpan.FromMinutes(1),
            MaxResponseDrainSize = 0, ResponseDrainTimeout = TimeSpan.Zero,
            ConnectCallback = async (context, token) =>
            {
                if (!scope.CanConnect(context.DnsEndPoint.Host, context.DnsEndPoint.Port)) throw new HttpRequestException("HTTP-адрес вне разрешённой области.");
                var socket = new Socket(AddressFamily.InterNetwork, SocketType.Stream, ProtocolType.Tcp);
                try
                {
                    socket.Bind(new IPEndPoint(scope.Network.LocalIpv4, 0));
                    IdentitySocketScope.SelectInterface(socket, scope.Network);
                    await socket.ConnectAsync(new IPEndPoint(scope.Address, scope.Port), token).ConfigureAwait(false);
                    return new NetworkStream(socket, ownsSocket: true);
                }
                catch { socket.Dispose(); throw; }
            }
        };
        return new HttpClient(handler) { Timeout = Timeout.InfiniteTimeSpan, DefaultRequestVersion = HttpVersion.Version11,
            DefaultVersionPolicy = HttpVersionPolicy.RequestVersionExact };
    }
    public void Dispose() => _candidates.Dispose();

    private sealed record Reply(Uri Url, int? Code = null, string ContentType = "", string Charset = "", string Server = "",
        byte[]? Body = null, Uri? Redirect = null, string Problem = "", bool Limited = false, Uri? External = null, bool Blocked = false)
    {
        public bool IsHtml => ContentType is "text/html" or "application/xhtml+xml";
    }
    private sealed class SiteCrawler(HttpSiteScope scope, HttpClient client, HttpSiteDiscoveryOptions options)
    {
        private readonly ConcurrentDictionary<string, Lazy<Task<(HttpRobotsRules Rules, string Problem)>>> _robots = new();
        private readonly ConcurrentDictionary<string, int> _requests = new();
        private readonly ConcurrentDictionary<string, byte> _visited = new();
        private int _totalRequests;
        private string _httpEvidence = "";
        private string _server = "";
        public async Task CheckAsync(HttpSiteResult initial, Action<HttpSiteResult> update, CancellationToken token)
        {
            using var budget = CancellationTokenSource.CreateLinkedTokenSource(token); budget.CancelAfter(options.SiteTimeout);
            var site = initial; var pages = new Dictionary<string, HttpPage>(); var external = new HashSet<string>();
            var partial = false; var notes = new HashSet<string>();
            void Publish(bool finished = false)
            {
                site = site with { Pages = Array.AsReadOnly(pages.Values.ToArray()), ExternalLinks = Array.AsReadOnly(external.Take(30).ToArray()),
                    RequestsChecked = _totalRequests, IsPartial = partial, Message = string.Join(" ", notes),
                    HttpConfirmed = site.HttpConfirmed || _httpEvidence.Length > 0, Evidence = _httpEvidence,
                    Server = site.Server.Length > 0 ? site.Server : _server };
                if (finished && site.State == HttpSiteState.Checking) site = site with { State = site.HttpConfirmed ? HttpSiteState.HttpConfirmed : HttpSiteState.NotChecked };
                update(site);
            }
            void Observe(Reply reply)
            {
                if (reply.External is not null && external.Count < 30) external.Add(reply.External.AbsoluteUri);
                if (reply.Problem.Length > 0) notes.Add(reply.Problem);
                partial |= reply.Limited || reply.Problem.Length > 0 && !reply.Blocked;
                if (reply.Code is not null) site = site with { HttpConfirmed = true, StatusCode = reply.Code,
                    ContentType = reply.ContentType, Server = reply.Server, StartUrl = reply.Url };
            }
            try
            {
                var first = await FetchAsync(initial.Origin, true, budget.Token).ConfigureAwait(false);
                Observe(first);
                if (first.Code is not null && first.External is null) site = site with { Origin = HttpSiteScope.Origin(first.Url) };
                if (first.Code is 401 or 403)
                { site = site with { State = HttpSiteState.AccessRestricted }; Publish(true); return; }
                if (first.Code == 404 || first.Code == 200 && (!first.IsHtml || first.Body is null) && !first.Limited)
                {
                    foreach (var path in new[] { "/index.html", "/index.htm", "/default.aspx", "/index.php" })
                    {
                        var fallback = await FetchAsync(new Uri(first.Url, path), true, budget.Token).ConfigureAwait(false);
                        Observe(fallback);
                        if (fallback.Code is 401 or 403) { first = fallback; break; }
                        if (fallback.Code == 200 && fallback.IsHtml && fallback.Body is not null) { first = fallback; break; }
                    }
                }
                // The root status remains meaningful even if optional fallbacks were unavailable.
                Observe(first);
                if (first.Code is not null && first.External is null) site = site with { Origin = HttpSiteScope.Origin(first.Url) };
                if (first.Code is 401 or 403) site = site with { State = HttpSiteState.AccessRestricted };
                else if (first.Code == 200 && first.IsHtml && first.Body is not null)
                {
                    site = site with { Origin = HttpSiteScope.Origin(first.Url), StartUrl = first.Url, State = HttpSiteState.SiteFound };
                    var queue = new Queue<(Uri Url, int Depth)>(); var queued = new HashSet<string>();
                    void AddPage(Reply reply, int depth)
                    {
                        using var document = new HtmlParser().ParseDocument(Decode(reply.Body!, reply.Charset));
                        var title = ProbeIo.Clean(document.Title, 512);
                        pages.TryAdd(reply.Url.AbsoluteUri, new(reply.Url, reply.Code!.Value, title, depth == 0 ? "Стартовая страница" : "Найдена по ссылке"));
                        if (depth == 0) site = site with { Title = title };
                        var basis = reply.Url;
                        var baseHref = document.QuerySelector("base[href]")?.GetAttribute("href");
                        if (baseHref is not null && Uri.TryCreate(basis, baseHref, out var htmlBase)) basis = htmlBase;
                        foreach (var anchor in document.QuerySelectorAll("a[href]"))
                        {
                            var href = anchor.GetAttribute("href");
                            if (href is null || href.Length > 2048 || !Uri.TryCreate(basis, href, out var raw)) continue;
                            var link = HttpSiteScope.Normalize(basis, href);
                            if (link is null || !HttpSiteScope.SameOrigin(link, site.Origin))
                            { if (raw.Scheme is "http" or "https" && raw.UserInfo.Length == 0 && external.Count < 30) external.Add(raw.AbsoluteUri); continue; }
                            if (!HttpSiteScope.IsPageLink(link) || pages.ContainsKey(link.AbsoluteUri) || queued.Contains(link.AbsoluteUri)) continue;
                            if (depth >= options.MaxDepth || queued.Count >= options.RequestsPerSite) { partial = true; continue; }
                            queued.Add(link.AbsoluteUri);
                            queue.Enqueue((link, depth + 1));
                        }
                    }
                    AddPage(first, 0); Publish();
                    while (queue.Count > 0 && pages.Count < options.MaxPages)
                    {
                        var batch = new List<(Uri Url, int Depth)>();
                        while (batch.Count < Math.Min(options.ConcurrentRequestsPerSite, options.MaxPages - pages.Count) && queue.TryDequeue(out var work))
                            if (!pages.ContainsKey(work.Url.AbsoluteUri)) batch.Add(work);
                        var replies = await Task.WhenAll(batch.Select(async work => (Reply: await FetchAsync(work.Url, false, budget.Token).ConfigureAwait(false), work.Depth))).ConfigureAwait(false);
                        foreach (var item in replies)
                        {
                            if (item.Reply.External is { } outside && external.Count < 30) external.Add(outside.AbsoluteUri);
                            partial |= item.Reply.Limited || item.Reply.Problem.Length > 0 && !item.Reply.Blocked;
                            if (item.Reply.Problem.Length > 0) notes.Add(item.Reply.Problem);
                            if (item.Reply.Code == 200 && item.Reply.IsHtml && item.Reply.Body is not null) AddPage(item.Reply, item.Depth);
                        }
                        Publish();
                    }
                    if (queue.Count > 0) { partial = true; notes.Add("Достигнут предел HTML-страниц."); }
                }
                else site = site with { State = first.Code == 404 ? HttpSiteState.StartPageNotFound : first.Code is null && first.Problem.Length > 0 && !first.Blocked ?
                    HttpSiteState.ConnectionError : site.HttpConfirmed ? HttpSiteState.HttpConfirmed : HttpSiteState.NotChecked };
            }
            catch (OperationCanceledException) when (!token.IsCancellationRequested)
            { partial = true; notes.Add("Истёк общий лимит времени поиска страниц сайта."); }
            finally { Publish(true); }
        }
        private async Task<Reply> FetchAsync(Uri start, bool confirmNames, CancellationToken token)
        {
            var url = start; var visited = new HashSet<string>(); int? lastCode = null;
            for (var hops = 0; ; hops++)
            {
                token.ThrowIfCancellationRequested();
                if (!await scope.AllowAsync(url, confirmNames, token).ConfigureAwait(false) ||
                    !confirmNames && !HttpSiteScope.SameOrigin(start, url))
                    return new(start, lastCode, Problem: "Переход за пределы разрешённого HTTP-источника не выполнен.", External: url);
                if (!HttpSiteScope.IsPageLink(url)) return new(start, lastCode, Problem: "Ссылка на файл или действие пропущена.", Blocked: true);
                if (!visited.Add(url.AbsoluteUri)) return new(url, lastCode, Problem: "Обнаружен цикл перенаправлений.", Limited: true);
                var rules = await _robots.GetOrAdd(HttpSiteScope.Origin(url).AbsoluteUri, _ => new Lazy<Task<(HttpRobotsRules Rules, string Problem)>>(
                    () => ReadRobotsAsync(HttpSiteScope.Origin(url), token))).Value.ConfigureAwait(false);
                if (!rules.Rules.Allows(url)) return new(url, lastCode, Problem: rules.Problem.Length > 0 ? rules.Problem : "Обход URL запрещён robots.txt.",
                    Limited: true, Blocked: rules.Problem.Length == 0);
                if (!_visited.TryAdd(url.AbsoluteUri, 0)) return new(url, lastCode, Problem: "Повторный запрос URL пропущен.");
                var reply = await SendAsync(url, false, token).ConfigureAwait(false);
                if (reply.Redirect is null) return reply;
                lastCode = reply.Code;
                if (hops >= options.MaxRedirects) return reply with { Problem = "Достигнут предел перенаправлений.", Limited = true };
                url = reply.Redirect;
            }
        }
        private async Task<(HttpRobotsRules Rules, string Problem)> ReadRobotsAsync(Uri origin, CancellationToken token)
        {
            var url = new Uri(origin, "robots.txt"); var visited = new HashSet<string>();
            for (var hops = 0; hops <= options.MaxRedirects; hops++)
            {
                if (!HttpSiteScope.SameOrigin(origin, url) || !HttpSiteScope.IsReadOnly(url) ||
                    !await scope.AllowAsync(url, false, token).ConfigureAwait(false) || !visited.Add(url.AbsoluteUri))
                    return (HttpRobotsRules.DenyAll, "Не удалось безопасно проверить robots.txt: перенаправление за пределы источника или цикл.");
                var reply = await SendAsync(url, true, token).ConfigureAwait(false);
                if (reply.Redirect is { } next) { url = next; continue; }
                if (reply.Limited || reply.Problem.Length > 0) return (HttpRobotsRules.DenyAll, "Не удалось получить robots.txt: " + reply.Problem);
                if (reply.Code == 200 && reply.Body is not null) return (HttpRobotsRules.Parse(Encoding.UTF8.GetString(reply.Body)), "");
                return reply.Code is >= 400 and < 500 && reply.Code is not (401 or 403) ? (HttpRobotsRules.AllowAll, "") :
                    (HttpRobotsRules.DenyAll, $"robots.txt недоступен (HTTP {reply.Code}); обход пропущен.");
            }
            return (HttpRobotsRules.DenyAll, "Достигнут предел перенаправлений robots.txt.");
        }
        private async Task<Reply> SendAsync(Uri url, bool robots, CancellationToken token)
        {
            if (_requests.AddOrUpdate(HttpSiteScope.Origin(url).AbsoluteUri, 1, (_, n) => n + 1) > options.RequestsPerSite)
                return new(url, Problem: "Достигнут предел HTTP-запросов сайта.", Limited: true);
            using var deadline = CancellationTokenSource.CreateLinkedTokenSource(token); deadline.CancelAfter(options.RequestTimeout);
            var reply = new Reply(url);
            try
            {
                using var request = new HttpRequestMessage(HttpMethod.Get, url);
                request.Headers.UserAgent.ParseAdd("WirelessSecurityAnalyzer/" + typeof(HttpSiteDiscovery).Assembly.GetName().Version?.Major);
                request.Headers.Accept.ParseAdd(robots ? "text/plain" : "text/html, application/xhtml+xml");
                Interlocked.Increment(ref _totalRequests);
                using var response = await client.SendAsync(request, HttpCompletionOption.ResponseHeadersRead, deadline.Token).ConfigureAwait(false);
                var code = (int)response.StatusCode;
                if (code is < 100 or > 599) return new(url, Problem: "Некорректный код HTTP-ответа.");
                reply = reply with { Code = code, ContentType = response.Content.Headers.ContentType?.MediaType?.ToLowerInvariant() ?? "",
                    Charset = response.Content.Headers.ContentType?.CharSet?.Trim('"', '\'') ?? "", Server = ProbeIo.Clean(response.Headers.Server.ToString(), 256) };
                _httpEvidence = $"GET {url.AbsoluteUri}: HTTP {code}.";
                if (reply.Server.Length > 0) _server = reply.Server;
                if (code is 301 or 302 or 303 or 307 or 308)
                {
                    if (response.Headers.Location is null || !Uri.TryCreate(url, response.Headers.Location, out var location))
                        return reply with { Problem = "HTTP-перенаправление без корректного Location." };
                    var normalized = HttpSiteScope.Normalize(url, location.AbsoluteUri);
                    var outside = location.Scheme is "http" or "https" ? new UriBuilder(location) { UserName = "", Password = "" }.Uri : null;
                    return normalized is null ? reply with { External = outside, Problem = "Перенаправление вне обычного HTTP без учётных данных не выполнялось." } : reply with { Redirect = normalized };
                }
                if (code != 200 || !robots && !reply.IsHtml) return reply;
                if (robots && reply.ContentType is not ("" or "text/plain" or "text/html" or "application/xhtml+xml"))
                    return reply with { Problem = "robots.txt имеет неподдерживаемый Content-Type; тело не читалось." };
                if (response.Content.Headers.ContentDisposition?.DispositionType.Equals("attachment", StringComparison.OrdinalIgnoreCase) == true)
                    return reply with { Problem = "Вложение не загружалось." };
                var limit = robots ? Math.Min(options.MaxHtmlBytes, 512 * 1024) : options.MaxHtmlBytes;
                if (response.Content.Headers.ContentLength > limit) return reply with { Limited = true, Problem = "Ответ превышает ограничение размера." };
                await using var body = await response.Content.ReadAsStreamAsync(deadline.Token).ConfigureAwait(false);
                using var collected = new MemoryStream(); var buffer = new byte[8192];
                while (collected.Length <= limit)
                {
                    var count = await body.ReadAsync(buffer.AsMemory(0, Math.Min(buffer.Length, limit + 1 - (int)collected.Length)), deadline.Token).ConfigureAwait(false);
                    if (count == 0) return reply with { Body = collected.ToArray() };
                    collected.Write(buffer, 0, count);
                }
                return reply with { Limited = true, Problem = "Ответ превышает ограничение размера." };
            }
            catch (OperationCanceledException) { token.ThrowIfCancellationRequested(); return reply with { Problem = "Истёк таймаут HTTP-запроса.", Limited = true }; }
            catch (Exception ex) when (ex is HttpRequestException or IOException or SocketException)
            { return reply with { Problem = "Ошибка HTTP-соединения: " + ex.GetType().Name + "." }; }
        }
        private static string Decode(byte[] bytes, string charset)
        {
            Encoding encoding = Encoding.UTF8;
            if (charset.Length == 0)
            {
                using var header = new HtmlParser().ParseDocument(Encoding.Latin1.GetString(bytes, 0, Math.Min(bytes.Length, 4096)));
                charset = header.QuerySelector("meta[charset]")?.GetAttribute("charset") ?? "";
                if (charset.Length == 0 && MediaTypeHeaderValue.TryParse(header.QuerySelector("meta[http-equiv='Content-Type' i]")?.GetAttribute("content"), out var meta)) charset = meta.CharSet ?? "";
            }
            try { if (charset.Length > 0) encoding = Encoding.GetEncoding(charset.Trim('"', '\'')); } catch (ArgumentException) { }
            using var stream = new MemoryStream(bytes); using var reader = new StreamReader(stream, encoding, detectEncodingFromByteOrderMarks: true);
            return reader.ReadToEnd();
        }
    }
}
