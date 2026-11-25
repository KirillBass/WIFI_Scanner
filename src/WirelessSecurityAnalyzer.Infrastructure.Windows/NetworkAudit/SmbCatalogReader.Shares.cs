using System.ComponentModel;
using System.Diagnostics;
using System.Net;
using System.Runtime.InteropServices;
using WirelessSecurityAnalyzer.Core.Models;
using WirelessSecurityAnalyzer.Core.NetworkAudit;

namespace WirelessSecurityAnalyzer.Infrastructure.Windows.NetworkAudit;

public sealed partial class SmbCatalogReader
{
    private const int MoreData = 234;
    private const int InvalidData = 13;
    private const uint ShareTypeMask = 0xff;
    private const uint SpecialShare = 0x80000000;

    public async Task<SmbShareListing> ListAsync(LocalNetworkInfo network, AuditRow endpoint, NetworkCredential? credential,
        CancellationToken token)
    {
        token.ThrowIfCancellationRequested();
        if (EndpointProblem(network, endpoint) is { } problem)
            return new([], problem.Access, CatalogState.Failed, problem.Message);
        if (!OperatingSystem.IsWindows())
            return new([], ResourceAccess.Unsupported, CatalogState.Failed, "Список общих папок запрашивается через клиент Windows.");
        if (!await _call.WaitAsync(0, token).ConfigureAwait(false))
            return new([], ResourceAccess.Unavailable, CatalogState.Failed, "Ожидается завершение предыдущего запроса Windows.");

        var found = new SortedDictionary<string, SmbShare>(StringComparer.OrdinalIgnoreCase);
        var server = @"\\" + endpoint.Address;
        var watch = Stopwatch.StartNew();
        using var deadline = CancellationTokenSource.CreateLinkedTokenSource(token);
        deadline.CancelAfter(TimeSpan.FromSeconds(45));
        SmbShareListing Result(ResourceAccess access, CatalogState state, string message) =>
            new(Array.AsReadOnly(found.Values.ToArray()), access, state, message);
        SmbShareListing Failure(ResourceAccess access, string message) =>
            Result(access, found.Count == 0 ? CatalogState.Failed : CatalogState.Partial, message);

        try
        {
            return await Task.Run(() =>
            {
                deadline.Token.ThrowIfCancellationRequested();
                if (!UsesSelectedInterface(network, endpoint.Target.Address))
                    return Failure(ResourceAccess.Unavailable, "Маршрут Windows проходит через другой интерфейс.");

                return WithAccount(credential, () =>
                {
                    CollectShares(server, found, resume => ReadSharePage(server, resume, deadline.Token), deadline.Token);
                    return Result(ResourceAccess.Granted, CatalogState.Complete, found.Count == 0
                        ? "Сервер не опубликовал видимых общих папок для этой учётной записи."
                        : "Выберите папку, чтобы проверить доступ и посмотреть содержимое.");
                });
            }, deadline.Token).ConfigureAwait(false);
        }
        catch (OperationCanceledException) when (!token.IsCancellationRequested)
        {
            return Failure(ResourceAccess.Unavailable, "Истекло время ожидания списка общих папок.");
        }
        catch (Win32Exception ex)
        {
            token.ThrowIfCancellationRequested();
            logger.Debug("SMB share listing {Address}:{Port}: Windows code {Code}", endpoint.Address, endpoint.Port, ex.NativeErrorCode);
            return ex.NativeErrorCode switch
            {
                5 => Failure(ResourceAccess.Denied, "Отказано в получении списка общих папок."),
                1219 => Failure(ResourceAccess.AuthenticationRequired, "Windows уже подключена к серверу с другой учётной записью (1219)."),
                86 or 1244 or 1326 or 1330 or 1331 =>
                    Failure(ResourceAccess.AuthenticationRequired, "Требуется авторизация. Проверьте учётную запись."),
                50 or 124 => Failure(ResourceAccess.Unsupported, "Сервер не поддерживает перечисление общих папок."),
                53 or 64 or 67 or 1722 or 2351 => Failure(ResourceAccess.Unavailable, "Не удалось подключиться к службе общих папок."),
                121 or 1460 => Failure(ResourceAccess.Unavailable, "Истекло время ожидания списка общих папок."),
                _ => Failure(ResourceAccess.Unavailable, $"Ошибка перечисления общих папок (код Windows {ex.NativeErrorCode}).")
            };
        }
        finally
        {
            _call.Release();
            logger.Debug("SMB share listing {Address}:{Port}: shares {Count}, cancelled {Cancelled}, elapsed {ElapsedMs} ms",
                endpoint.Address, endpoint.Port, found.Count, token.IsCancellationRequested, watch.ElapsedMilliseconds);
        }
    }

    internal sealed record SharePage(int Status, uint Resume, IReadOnlyList<(string Name, uint Type)> Entries);

    internal static void CollectShares(string server, IDictionary<string, SmbShare> found, Func<uint, SharePage> getPage, CancellationToken token)
    {
        uint resume = 0;
        var visited = new HashSet<uint> { resume };
        while (true)
        {
            token.ThrowIfCancellationRequested();
            var page = getPage(resume);
            token.ThrowIfCancellationRequested();
            if (page.Status is not (0 or MoreData)) throw new Win32Exception(page.Status);
            foreach (var (name, type) in page.Entries)
            {
                token.ThrowIfCancellationRequested();
                if ((type & (ShareTypeMask | SpecialShare)) == 0 && ResourcePath.IsVisibleShareName(name))
                    found.TryAdd(name, new(name, $@"{server}\{name}"));
            }

            if (page.Status == 0) return;
            resume = page.Resume;
            if (!visited.Add(resume)) throw new Win32Exception(InvalidData);
        }
    }

    private static SharePage ReadSharePage(string server, uint resume, CancellationToken token)
    {
        const uint preferredBufferBytes = 64 * 1024;
        var status = NetShareEnum(server, 1, out var buffer, preferredBufferBytes, out var count, out _, ref resume);
        try
        {
            token.ThrowIfCancellationRequested();
            if (status is not (0 or MoreData)) return new(status, resume, []);
            if (count > 0 && buffer == IntPtr.Zero) throw new Win32Exception(InvalidData);

            var entries = new List<(string, uint)>();
            var entrySize = Marshal.SizeOf<ShareInfo1>();
            for (var index = 0; index < count; index++)
            {
                token.ThrowIfCancellationRequested();
                var entry = Marshal.PtrToStructure<ShareInfo1>(buffer + checked(index * entrySize));
                if (Marshal.PtrToStringUni(entry.Name) is { } name) entries.Add((name, entry.Type));
            }
            return new(status, resume, entries);
        }
        finally
        {
            if (buffer != IntPtr.Zero) NetApiBufferFree(buffer);
        }
    }

    [StructLayout(LayoutKind.Sequential)]
    private readonly struct ShareInfo1
    {
        public readonly IntPtr Name;
        public readonly uint Type;
        public readonly IntPtr Remark;
    }

    [DllImport("Netapi32.dll", CharSet = CharSet.Unicode, ExactSpelling = true)]
    private static extern int NetShareEnum(string server, uint level, out IntPtr buffer, uint preferredMaximumLength,
        out uint entriesRead, out uint totalEntries, ref uint resume);
}
