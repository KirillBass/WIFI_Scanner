using System.Collections.Concurrent;
using System.Net;
using System.Net.NetworkInformation;
using System.Net.Sockets;
using System.Text;
using System.Text.RegularExpressions;
using WirelessSecurityAnalyzer.Core.Models;
using WirelessSecurityAnalyzer.Infrastructure.Windows.Network;
using WirelessSecurityAnalyzer.Infrastructure.Windows.Network.Identity;

namespace WirelessSecurityAnalyzer.Infrastructure.Windows.NetworkAudit;

public interface IHttpSiteHostResolver
{
    Task<bool> MatchesAsync(LocalNetworkInfo network, string hostname, IPAddress address, CancellationToken token);
}

/// <summary>Forward confirmation through the existing local DNS/mDNS transport. Never uses system/public DNS.</summary>
public sealed class HttpSiteHostResolver(IIdentityDatagramClient datagrams, ILocalDnsServerProvider? dnsServers = null) : IHttpSiteHostResolver
{
    public async Task<bool> MatchesAsync(LocalNetworkInfo network, string hostname, IPAddress address, CancellationToken token)
    {
        var servers = (dnsServers ?? new LocalDnsServerProvider()).GetServers(network).Where(network.Subnet.ContainsHost)
            .Distinct().Take(3).Select(ip => new IPEndPoint(ip, 53)).ToList();
        if (hostname.EndsWith(".local", StringComparison.OrdinalIgnoreCase)) servers.Add(new(IPAddress.Parse("224.0.0.251"), 5353));
        foreach (var server in servers)
        {
            var id = DnsPacket.NewId(); var matched = false;
            try
            {
                await datagrams.QueryAsync(network, server, [DnsPacket.Query(id, [new(hostname, 1)])], TimeSpan.FromMilliseconds(300), packet =>
                {
                    try
                    {
                        var message = DnsPacket.Parse(packet.Data);
                        if (!message.IsAnswer || server.Port == 53 && (message.Id != id || !message.Questions.Any(q =>
                            q.Type == 1 && q.Name.Equals(hostname, StringComparison.OrdinalIgnoreCase)))) return;
                        var records = message.Records.Where(r => r.Type == 1 && r.Class == 1 && r.Ttl > 0 &&
                            r.Name.Equals(hostname, StringComparison.OrdinalIgnoreCase)).ToArray();
                        matched = records.Length > 0 && records.All(r => address.Equals(r.Address));
                    }
                    catch (FormatException) { }
                }, token, () => matched).ConfigureAwait(false);
            }
            catch (SocketException) { }
            if (matched) return true;
        }
        return false;
    }
}

internal sealed class HttpSiteScope(LocalNetworkInfo network, IPAddress address, int port, IHttpSiteHostResolver resolver,
    IReadOnlySet<IPAddress> localAddresses, bool includeLocal = false)
{
    private readonly ConcurrentDictionary<string, bool> _hosts = new(StringComparer.OrdinalIgnoreCase);
    public IPAddress Address => address;
    public int Port => port;
    public LocalNetworkInfo Network => network;
    public bool IsRemote => network.Subnet.ContainsHost(address) && !IPAddress.IsLoopback(address) &&
        !address.Equals(network.LocalIpv4) && !localAddresses.Contains(address);
    public bool IsAllowedTarget => IsRemote || includeLocal && address.Equals(network.LocalIpv4) && network.Subnet.ContainsHost(address);
    public static Uri Origin(Uri url) => new(url.GetLeftPart(UriPartial.Authority) + "/");
    public static bool SameOrigin(Uri first, Uri second) => first.Scheme == second.Scheme && first.Port == second.Port &&
        first.IdnHost.Equals(second.IdnHost, StringComparison.OrdinalIgnoreCase);
    public bool CanConnect(string host, int destinationPort) => IsAllowedTarget && destinationPort == port &&
        (IPAddress.TryParse(host, out var ip) ? address.Equals(ip) : _hosts.GetValueOrDefault(host.TrimEnd('.')));
    public async Task<bool> AllowAsync(Uri uri, bool confirmName, CancellationToken token)
    {
        if (!IsAllowedTarget || !IsSafe(uri) || uri.Port != port) return false;
        if (IPAddress.TryParse(uri.Host, out var ip)) return address.Equals(ip);
        var host = uri.IdnHost.TrimEnd('.');
        if (host.Equals("localhost", StringComparison.OrdinalIgnoreCase) || host.EndsWith(".localhost", StringComparison.OrdinalIgnoreCase)) return false;
        if (_hosts.TryGetValue(host, out var known)) return known;
        if (!confirmName || _hosts.Count >= 8) return false;
        var allowed = await resolver.MatchesAsync(network, host, address, token).ConfigureAwait(false);
        _hosts.TryAdd(host, allowed);
        return allowed;
    }
    public static bool IsSafe(Uri uri) => uri.IsAbsoluteUri && uri.Scheme == "http" && uri.UserInfo.Length == 0 &&
        uri.AbsoluteUri.Length <= 2048 && uri.HostNameType is UriHostNameType.IPv4 or UriHostNameType.Dns;
    public static Uri? Normalize(Uri basis, string? href)
    {
        if (string.IsNullOrWhiteSpace(href) || href.Length > 2048 || !Uri.TryCreate(basis, href.Trim(), out var uri) || !IsSafe(uri)) return null;
        return new UriBuilder(uri) { Fragment = "" }.Uri;
    }
    private static readonly HashSet<string> Actions = new(StringComparer.OrdinalIgnoreCase)
    { "logout", "logoff", "signout", "delete", "remove", "reset", "reboot", "restart", "shutdown", "upload", "download",
      "execute", "exec", "run", "save", "update", "edit", "create", "add", "install", "uninstall", "enable", "disable",
      "apply", "set", "submit", "action", "cmd", "command", "do" };
    private static readonly HashSet<string> PageExtensions = new(StringComparer.OrdinalIgnoreCase)
    { "", ".html", ".htm", ".shtml", ".php", ".asp", ".aspx", ".jsp", ".jspx", ".cgi", ".cfm" };
    public static bool IsPageLink(Uri uri)
        => IsReadOnly(uri) && PageExtensions.Contains(Path.GetExtension(uri.AbsolutePath.TrimEnd('/')));
    public static bool IsReadOnly(Uri uri)
    {
        var path = uri.PathAndQuery;
        for (var i = 0; i < 2; i++) path = Uri.UnescapeDataString(path);
        var words = path.Split(['/','\\','?','&','=','-','_','.','+',';',':'], StringSplitOptions.RemoveEmptyEntries);
        return !words.Any(Actions.Contains);
    }
    public static IReadOnlySet<IPAddress> LocalAddresses()
    {
        try { return NetworkInterface.GetAllNetworkInterfaces().SelectMany(n => n.GetIPProperties().UnicastAddresses).Select(a => a.Address).ToHashSet(); }
        catch (NetworkInformationException) { return new HashSet<IPAddress>(); }
    }
}

internal sealed class HttpRobotsRules
{
    private readonly (Regex Pattern, int Length, bool Allow)[] _rules;
    private HttpRobotsRules(IEnumerable<(string Path, bool Allow)> rules) => _rules = rules.Where(r => r.Path.Length is > 0 and <= 2048)
        .Select(r => (new Regex("^" + Regex.Escape(Normalize(r.Path.TrimEnd('$'))).Replace("\\*", ".*") +
            (r.Path.EndsWith('$') ? "$" : ""), RegexOptions.CultureInvariant | RegexOptions.NonBacktracking), r.Path.Count(c => c != '*'), r.Allow)).ToArray();
    public static HttpRobotsRules AllowAll { get; } = new([]);
    public static HttpRobotsRules DenyAll { get; } = new([("/", false)]);
    public bool Allows(Uri url)
    {
        var path = Normalize(url.PathAndQuery);
        var matches = _rules.Where(r => r.Pattern.IsMatch(path)).OrderByDescending(r => r.Length).ThenByDescending(r => r.Allow).ToArray();
        return matches.Length == 0 || matches[0].Allow;
    }
    public static HttpRobotsRules Parse(string text)
    {
        var groups = new List<(List<string> Agents, List<(string, bool)> Rules)>();
        var agents = new List<string>(); var rules = new List<(string, bool)>(); var hasDirectives = false;
        foreach (var raw in text.Split('\n').Take(16000))
        {
            var line = raw.Split('#', 2)[0].Trim(); var colon = line.IndexOf(':');
            if (colon < 0) continue;
            var key = line[..colon].Trim(); var value = line[(colon + 1)..].Trim();
            if (key.Equals("user-agent", StringComparison.OrdinalIgnoreCase))
            {
                if (hasDirectives) { groups.Add((agents, rules)); agents = []; rules = []; hasDirectives = false; }
                agents.Add(value);
            }
            else if (agents.Count > 0 && (key.Equals("allow", StringComparison.OrdinalIgnoreCase) || key.Equals("disallow", StringComparison.OrdinalIgnoreCase)))
            {
                hasDirectives = true;
                if (!value.StartsWith('/')) continue;
                if (value.Length > 2048 || rules.Count + groups.Sum(g => g.Rules.Count) >= 512) return DenyAll;
                rules.Add((value, key.Equals("allow", StringComparison.OrdinalIgnoreCase)));
            }
        }
        groups.Add((agents, rules));
        var applicable = groups.Select(g => (Group: g, Weight: g.Agents.Select(a => a == "*" ? 0 : a.Length > 0 &&
            "WirelessSecurityAnalyzer".Contains(a, StringComparison.OrdinalIgnoreCase) ? a.Length : -1).DefaultIfEmpty(-1).Max())).ToArray();
        var weight = applicable.Select(a => a.Weight).DefaultIfEmpty(-1).Max();
        return new(applicable.Where(a => a.Weight >= 0 && a.Weight == weight).SelectMany(a => a.Group.Rules));
    }
    private static string Normalize(string value)
    {
        var result = new StringBuilder();
        for (var i = 0; i < value.Length; i++)
        {
            if (value[i] == '%' && i + 2 < value.Length && byte.TryParse(value.AsSpan(i + 1, 2), System.Globalization.NumberStyles.HexNumber, null, out var code))
            {
                var c = (char)code;
                result.Append(char.IsAsciiLetterOrDigit(c) || c is '-' or '_' or '.' or '~' ? c.ToString() : $"%{code:X2}"); i += 2;
            }
            else if (value[i] > 127)
            {
                var rune = char.IsHighSurrogate(value[i]) && i + 1 < value.Length ? value.Substring(i++, 2) : value[i].ToString();
                foreach (var b in Encoding.UTF8.GetBytes(rune)) result.Append($"%{b:X2}");
            }
            else result.Append(value[i]);
        }
        return result.ToString();
    }
}
