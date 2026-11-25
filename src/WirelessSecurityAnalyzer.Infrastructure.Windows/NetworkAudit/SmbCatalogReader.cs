using System.ComponentModel;
using System.IO.Enumeration;
using System.Net;
using System.Runtime.InteropServices;
using System.Security.Principal;
using Microsoft.Win32.SafeHandles;
using Serilog;
using WirelessSecurityAnalyzer.Core.Models;
using WirelessSecurityAnalyzer.Core.NetworkAudit;
using WirelessSecurityAnalyzer.Infrastructure.Windows.Interop;

namespace WirelessSecurityAnalyzer.Infrastructure.Windows.NetworkAudit;

public sealed class SmbCatalogReader(ILogger logger) : IResourceCatalogReader
{
    private readonly SemaphoreSlim _call = new(1, 1);
    public string Protocol => "SMB";

    public async Task<CatalogResult> ReadAsync(LocalNetworkInfo network, AuditRow endpoint, string resourceRoot,
        IReadOnlyList<string> folders, NetworkCredential? credential, Action<ResourceEntry> publish, CancellationToken token)
    {
        if (!endpoint.HasFileService || TargetServiceMatcher.Family(endpoint.Protocol) != Protocol ||
            !network.Subnet.ContainsHost(endpoint.Target.Address))
            return Failure(ResourceAccess.Unavailable, "", "Служба вне текущей сети.");
        if (endpoint.Port != 445)
            return Failure(ResourceAccess.Unsupported, "", "Клиент SMB Windows использует TCP 445. Этот порт не будет подменён.");
        var share = ResourcePath.SmbShare(endpoint.Address, resourceRoot);
        if (share.Length == 0 || folders.Any(name => !ResourcePath.IsWindowsSegment(name)))
            return Failure(ResourceAccess.Unsupported, "", "Укажите UNC-путь известной общей папки на выбранном IP.");
        if (!await _call.WaitAsync(0, token).ConfigureAwait(false))
            return Failure(ResourceAccess.Unavailable, "", "Ожидается завершение предыдущего запроса Windows.");

        var server = @"\\" + endpoint.Address;
        var root = Path.Combine(server + @"\", share);
        var path = root;
        var count = 0;
        var watch = System.Diagnostics.Stopwatch.StartNew();
        using var deadline = CancellationTokenSource.CreateLinkedTokenSource(token);
        deadline.CancelAfter(TimeSpan.FromSeconds(45));
        try
        {
            return await Task.Run(() =>
            {
                deadline.Token.ThrowIfCancellationRequested();
                var destination = new SockaddrInet { Family = IpHelperNativeMethods.AfInet,
                    Ipv4Address = BitConverter.ToUInt32(endpoint.Target.Address.GetAddressBytes()) };
                if (!endpoint.Target.Address.Equals(network.LocalIpv4) &&
                    (IpHelperNativeMethods.GetBestInterfaceEx(ref destination, out var index) != 0 || index != network.InterfaceIndex))
                    return Failure(ResourceAccess.Unavailable, root, "Маршрут Windows проходит через другой интерфейс.");

                CatalogResult List()
                {
                    EnsureDirectShare(server, share);
                    deadline.Token.ThrowIfCancellationRequested();
                    VerifyDirectory(path);
                    foreach (var folder in folders)
                    {
                        path = Path.Combine(path, folder);
                        VerifyDirectory(path);
                        deadline.Token.ThrowIfCancellationRequested();
                    }

                    var entries = new FileSystemEnumerable<ResourceEntry>(path, static (ref FileSystemEntry entry) =>
                        new(entry.FileName.ToString(), entry.ToFullPath(), (entry.Attributes & FileAttributes.ReparsePoint) != 0
                            ? ResourceEntryKind.Link : entry.IsDirectory ? ResourceEntryKind.Folder : ResourceEntryKind.File,
                            entry.IsDirectory ? null : entry.Length, entry.CreationTimeUtc, entry.LastWriteTimeUtc),
                        new EnumerationOptions { RecurseSubdirectories = false, AttributesToSkip = 0, IgnoreInaccessible = false });
                    foreach (var entry in entries)
                    {
                        deadline.Token.ThrowIfCancellationRequested();
                        publish(entry);
                        count++;
                    }
                    deadline.Token.ThrowIfCancellationRequested();
                    return new(ResourceAccess.Granted, CatalogState.Complete, path, count == 0 ? "Каталог пуст." : "Каталог получен.");
                }

                if (credential is null) return List();
                if (!LogonUser(credential.UserName, string.IsNullOrEmpty(credential.Domain) ? null : credential.Domain,
                        credential.Password, 9 /* NEW_CREDENTIALS */, 3 /* WINNT50 */, out var accessToken))
                    throw new Win32Exception(Marshal.GetLastPInvokeError());
                using (accessToken) return WindowsIdentity.RunImpersonated(accessToken, List);
            }, deadline.Token).ConfigureAwait(false);
        }
        catch (OperationCanceledException) when (!token.IsCancellationRequested)
        {
            return Failure(ResourceAccess.Unavailable, path, "Истекло время ожидания ответа SMB.", count);
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or Win32Exception or NotSupportedException or System.Security.SecurityException)
        {
            token.ThrowIfCancellationRequested();
            var code = ex is Win32Exception win32 ? win32.NativeErrorCode : ex.HResult & 0xffff;
            logger.Debug("SMB catalogue {Address}:{Port}: {ErrorType}, code {Code}", endpoint.Address, endpoint.Port, ex.GetType().Name, code);
            return code switch
            {
                1219 => Failure(ResourceAccess.AuthenticationRequired, path, "Windows уже подключена к этому серверу с другими учётными данными (1219).", count),
                86 or 1326 or 1330 or 1331 => Failure(ResourceAccess.AuthenticationRequired, path, "Windows не приняла учётные данные.", count),
                5 => Failure(ResourceAccess.Denied, path, "Windows или сервер отказал в доступе.", count),
                2 or 3 or 67 or 2310 => Failure(ResourceAccess.Unavailable, path, "Сервер не нашёл указанную папку или ресурс.", count),
                50 or 124 or 4390 or 1240 => Failure(ResourceAccess.Unsupported, path, "Не удалось подтвердить, что ресурс доступен без DFS и перенаправлений.", count),
                1460 or 121 => Failure(ResourceAccess.Unavailable, path, "Истекло время ожидания ответа SMB.", count),
                _ => Failure(ResourceAccess.Unavailable, path, $"Не удалось получить каталог SMB (код Windows {code}).", count)
            };
        }
        finally
        {
            _call.Release();
            logger.Debug("SMB catalogue {Address}:{Port}: entries {Count}, cancelled {Cancelled}, elapsed {ElapsedMs} ms",
                endpoint.Address, endpoint.Port, count, token.IsCancellationRequested, watch.ElapsedMilliseconds);
        }
    }

    private static CatalogResult Failure(ResourceAccess access, string path, string message, int count = 0) =>
        new(access, count > 0 ? CatalogState.Partial : CatalogState.Failed, path, message);

    private static void VerifyDirectory(string path)
    {
        var attributes = File.GetAttributes(path);
        if ((attributes & FileAttributes.ReparsePoint) != 0) throw new Win32Exception(4390);
        if ((attributes & FileAttributes.Directory) == 0) throw new Win32Exception(3);
    }

    private static void EnsureDirectShare(string server, string share)
    {
        var status = NetShareGetInfo(server, share, 1005, out var buffer);
        try
        {
            if (status != 0) throw new Win32Exception(status);
            if (buffer == IntPtr.Zero || (Marshal.ReadInt32(buffer) & 3) != 0) throw new Win32Exception(50);
        }
        finally
        {
            if (buffer != IntPtr.Zero) NetApiBufferFree(buffer);
        }
    }

    [DllImport("Netapi32.dll", CharSet = CharSet.Unicode, ExactSpelling = true)]
    private static extern int NetShareGetInfo(string server, string share, int level, out IntPtr buffer);

    [DllImport("Netapi32.dll")]
    private static extern int NetApiBufferFree(IntPtr buffer);

    [DllImport("Advapi32.dll", EntryPoint = "LogonUserW", CharSet = CharSet.Unicode, ExactSpelling = true, SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool LogonUser(string user, string? domain, string password, int logonType, int provider,
        out SafeAccessTokenHandle token);
}
