using System.Collections.Concurrent;
using System.Net;
using System.Net.Sockets;
using Serilog;
using WirelessSecurityAnalyzer.Core.Interfaces;
using WirelessSecurityAnalyzer.Core.Models;

namespace WirelessSecurityAnalyzer.Infrastructure.Windows.Network;

public sealed class HostnameResolver(ILogger logger) : IHostnameResolver
{
    private readonly ConcurrentDictionary<string, CachedName> _cache = new();
    private readonly SemaphoreSlim _dnsGate = new(8, 8);

    public async Task<string?> ResolveAsync(LocalNetworkInfo network, IPAddress address, int timeoutMs,
        CancellationToken cancellationToken = default)
    {
        var key = $"{network.InterfaceId}|{network.LocalIpv4}/{network.PrefixLength}|{address}";
        if (_cache.TryGetValue(key, out var cached) && cached.ExpiresAt > DateTimeOffset.UtcNow) return cached.Name;
        using var timeout = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
        timeout.CancelAfter(timeoutMs);
        var acquired = false;
        Task<IPHostEntry>? lookup = null;
        try
        {
            await _dnsGate.WaitAsync(timeout.Token).ConfigureAwait(false);
            acquired = true;
            lookup = Dns.GetHostEntryAsync(address.ToString(), AddressFamily.InterNetwork, timeout.Token);
            var entry = await lookup.WaitAsync(timeout.Token).ConfigureAwait(false);
            if (string.IsNullOrWhiteSpace(entry.HostName) || IPAddress.TryParse(entry.HostName, out _)) return null;
            if (_cache.Count >= 2048) _cache.Clear();
            _cache[key] = new CachedName(entry.HostName, DateTimeOffset.UtcNow.AddMinutes(5));
            return entry.HostName;
        }
        catch (OperationCanceledException) when (!cancellationToken.IsCancellationRequested) { return null; }
        catch (SocketException exception) { logger.Debug(exception, "Reverse DNS unavailable for {Address}", address); return null; }
        finally
        {
            if (acquired)
            {
                if (lookup is { IsCompleted: false }) _ = ReleaseAfterLookupAsync(lookup);
                else _dnsGate.Release();
            }
        }
    }

    private async Task ReleaseAfterLookupAsync(Task<IPHostEntry> lookup)
    {
        try { await lookup.ConfigureAwait(false); }
        catch (Exception exception) { logger.Debug(exception, "Timed-out reverse DNS operation completed"); }
        finally { _dnsGate.Release(); }
    }

    private sealed record CachedName(string Name, DateTimeOffset ExpiresAt);
}
