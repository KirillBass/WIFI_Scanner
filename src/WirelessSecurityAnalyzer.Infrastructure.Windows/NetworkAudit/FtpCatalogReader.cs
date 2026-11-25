using System.Diagnostics;
using System.Net;
using System.Net.Sockets;
using System.Text;
using FluentFTP;
using FluentFTP.Exceptions;
using FluentFTP.Helpers;
using Serilog;
using WirelessSecurityAnalyzer.Core.Models;
using WirelessSecurityAnalyzer.Core.NetworkAudit;

namespace WirelessSecurityAnalyzer.Infrastructure.Windows.NetworkAudit;

public sealed class FtpCatalogReader(ILogger logger) : IResourceCatalogReader
{
    public string Protocol => "FTP";

    public async Task<CatalogResult> ReadAsync(LocalNetworkInfo network, AuditRow endpoint, string resourceRoot,
        IReadOnlyList<string> folders, NetworkCredential? credential, Action<ResourceEntry> publish, CancellationToken token)
    {
        if (!endpoint.HasFileService || endpoint.Protocol != Protocol || !network.Subnet.ContainsHost(endpoint.Target.Address) ||
            folders.Any(folder => !ResourcePath.IsSegment(folder)))
            return new(ResourceAccess.Unavailable, CatalogState.Failed, "", "Служба или папка вне области выбранного ресурса.");
        credential ??= new NetworkCredential("anonymous", "anonymous");
        if (credential.UserName.Length == 0 || credential.UserName.Any(char.IsControl) || credential.Password.Any(char.IsControl))
            return new(ResourceAccess.AuthenticationRequired, CatalogState.Failed, "", "Проверьте имя пользователя и пароль.");

        using var deadline = CancellationTokenSource.CreateLinkedTokenSource(token);
        deadline.CancelAfter(TimeSpan.FromSeconds(45));
        var ct = deadline.Token;
        var watch = Stopwatch.StartNew();
        var count = 0;
        var path = FormatPath(endpoint, "/");
        var loginCompleted = false;
        using var client = new CatalogClient(endpoint, network, credential);
        CatalogResult Fail(ResourceAccess access, string message) =>
            new(access, count > 0 ? CatalogState.Partial : CatalogState.Failed, path, message);
        try
        {
            await client.Connect(ct).ConfigureAwait(false);
            loginCompleted = true;
            var home = await ReadWorkingDirectoryAsync(client, ct).ConfigureAwait(false);
            if (resourceRoot.Length > 0 && !string.Equals(home, resourceRoot, StringComparison.Ordinal))
                return Fail(ResourceAccess.Unavailable, "Начальная папка FTP изменилась. Откройте корень заново.");
            var folder = folders.Count == 0 ? home : home.TrimEnd('/') + "/" + string.Join('/', folders);
            path = FormatPath(endpoint, folder);
            if (folders.Count > 0)
            {
                var reply = await client.Execute("CWD " + folder, ct).ConfigureAwait(false);
                if (reply.Code != "250") throw new FtpCommandException(reply);
                if (await ReadWorkingDirectoryAsync(client, ct).ConfigureAwait(false) != folder)
                    return Fail(ResourceAccess.Unsupported, "Сервер перенаправил запрос в другую папку.");
            }

            var parser = new FtpListParser(client);
            parser.Init(client.ServerOS, client.Config.ListingParser);
            var capabilities = client.Capabilities.ToList();
            var seen = new HashSet<string>(StringComparer.Ordinal);
            var malformed = false;
            bool AddLine(string line, bool machine)
            {
                if (line.Length == 0 || !machine && line.StartsWith("total ", StringComparison.Ordinal)) return true;
                FtpListItem? item;
                try { item = parser.ParseSingleLine(folder, line, capabilities, machine); }
                catch (FtpListParseException) { return false; }
                if (item is null) return false;
                if (item.Name is "." or "..") return true;
                if (!ResourcePath.IsSegment(item.Name)) return false;
                if (!seen.Add(item.Name)) return true;
                var kind = item.Type switch { FtpObjectType.File => ResourceEntryKind.File, FtpObjectType.Directory => ResourceEntryKind.Folder, _ => ResourceEntryKind.Link };
                publish(new(item.Name, FormatPath(endpoint, folder.TrimEnd('/') + "/" + item.Name), kind,
                    kind == ResourceEntryKind.File && item.Size >= 0 ? item.Size : null,
                    ToTimestamp(item.Created), ToTimestamp(item.Modified)));
                count++;
                return true;
            }
            var machine = client.HasFeature(FtpCapability.MLST);
            try
            {
                await client.ReadListingAsync(machine, line => malformed |= !AddLine(line, machine), ct).ConfigureAwait(false);
            }
            catch (FtpCommandException ex) when (machine && count == 0 && ex.CompletionCode is "500" or "501" or "502" or "504")
            {
                malformed = false;
                await client.ReadListingAsync(false, line => malformed |= !AddLine(line, false), ct).ConfigureAwait(false);
            }
            ct.ThrowIfCancellationRequested();
            if (malformed) return Fail(ResourceAccess.Granted, "Часть ответа FTP не удалось разобрать.");
            return new(ResourceAccess.Granted, CatalogState.Complete, path,
                count == 0 ? "Каталог пуст." : "Каталог получен.") { Root = home };
        }
        catch (OperationCanceledException) when (!token.IsCancellationRequested)
        {
            return Fail(ResourceAccess.Unavailable, "Истекло время ожидания ответа FTP.");
        }
        catch (FtpCommandException ex)
        {
            token.ThrowIfCancellationRequested();
            var code = ex.CompletionCode;
            if (code is "534" or "536" || code is "530" or "550" &&
                (ex.Message.Contains("TLS", StringComparison.OrdinalIgnoreCase) ||
                 ex.Message.Contains("SSL", StringComparison.OrdinalIgnoreCase)))
                return Fail(ResourceAccess.SecureConnectionRequired, "Требуется защищённое FTP-соединение.");
            if (ex is FtpAuthenticationException || code == "530")
                return Fail(ResourceAccess.AuthenticationRequired, "FTP-сервер отклонил вход. Проверьте учётные данные.");
            if (code == "550")
                return Fail(ResourceAccess.Denied, "FTP-сервер отказал в доступе или папка недоступна (550).");
            if (code is "425" or "426")
                return Fail(ResourceAccess.Unavailable, "FTP-сервер не открыл или прервал канал данных.");
            return Fail(ResourceAccess.Unavailable, "FTP-сервер не завершил операцию.");
        }
        catch (InvalidDataException)
        {
            return Fail(ResourceAccess.Unsupported, "FTP-сервер вернул неизвестный формат пути, протокола или каталога.");
        }
        catch (Exception ex) when (ex is IOException or SocketException or TimeoutException or FtpException)
        {
            token.ThrowIfCancellationRequested();
            logger.Debug("FTP catalogue {Address}:{Port}: {ErrorType}", endpoint.Address, endpoint.Port, ex.GetType().Name);
            return Fail(ResourceAccess.Unavailable, ex is TimeoutException ? "Истекло время ожидания ответа FTP." :
                loginCompleted ? "Соединение FTP прервано при получении каталога." : "Не удалось подключиться к FTP.");
        }
        finally
        {
            using var quit = new CancellationTokenSource(TimeSpan.FromSeconds(1));
            try { await client.Disconnect(quit.Token).ConfigureAwait(false); }
            catch (Exception ex) when (ex is IOException or SocketException or TimeoutException or FtpException or OperationCanceledException) { }
            logger.Debug("FTP catalogue {Address}:{Port}: entries {Count}, cancelled {Cancelled}, elapsed {ElapsedMs} ms",
                endpoint.Address, endpoint.Port, count, token.IsCancellationRequested, watch.ElapsedMilliseconds);
        }
    }

    private static DateTimeOffset? ToTimestamp(DateTime value) => value == DateTime.MinValue ? null : new(value);
    private static string FormatPath(AuditRow endpoint, string path) => $"ftp://{endpoint.Address}:{endpoint.Port}" +
        string.Join('/', path.Split('/').Select(Uri.EscapeDataString));

    private static async Task<string> ReadWorkingDirectoryAsync(AsyncFtpClient client, CancellationToken token)
    {
        var reply = await client.Execute("PWD", token).ConfigureAwait(false);
        if (reply.Code != "257") throw new FtpCommandException(reply);
        var message = reply.Message;
        if (message.Length == 0 || message[0] != '"') throw new InvalidDataException();
        var path = new StringBuilder();
        for (var index = 1; index < message.Length; index++)
        {
            if (message[index] != '"') { path.Append(message[index]); continue; }
            if (index + 1 < message.Length && message[index + 1] == '"') { path.Append('"'); index++; continue; }
            var result = path.ToString().TrimEnd('/');
            if (result.Length == 0 && path.Length == 1) return "/";
            if (result.StartsWith('/') && result[1..].Split('/').All(ResourcePath.IsSegment)) return result;
            break;
        }
        throw new InvalidDataException();
    }

    private sealed class CatalogClient(AuditRow endpoint, LocalNetworkInfo network, NetworkCredential credential)
        : AsyncFtpClient(endpoint.Address, credential, endpoint.Port, new FtpConfig
        {
            DataConnectionType = FtpDataConnectionType.PASVEX,
            SocketLocalIp = network.LocalIpv4,
            InternetProtocolVersions = FtpIpVersion.IPv4,
            ConnectTimeout = 6000, ReadTimeout = 8000, WriteTimeout = 8000,
            DataConnectionConnectTimeout = 6000, DataConnectionReadTimeout = 8000,
            SelfConnectMode = FtpSelfConnectMode.Never,
            LogToConsole = false, LogPassword = false, LogUserName = false,
            PostConnect = false, SanitizeMode = FtpSanitize.Throw
        })
    {
        protected override async Task Authenticate(CancellationToken token)
        {
            var reply = await Execute("SYST", token).ConfigureAwait(false);
            if (reply.Code != "215" || string.IsNullOrWhiteSpace(reply.Message))
            {
                if (reply.Code is "530" or "534" or "536") throw new FtpCommandException(reply);
                throw new InvalidDataException();
            }
            await base.Authenticate(token).ConfigureAwait(false);
        }

        protected override Task ConnectAsync(FtpSocketStream stream, string host, int port, FtpIpVersion versions, CancellationToken token)
        {
            if (!IPAddress.TryParse(host, out var address) || !address.Equals(endpoint.Target.Address))
                throw new InvalidDataException();
            return base.ConnectAsync(stream, host, port, versions, token);
        }

        public async Task ReadListingAsync(bool machine, Action<string> publish, CancellationToken token)
        {
            using var data = await OpenDataStreamAsync(machine ? "MLSD" : "LIST", 0, token).ConfigureAwait(false);
            using var listing = new StreamReader(data, Encoding, detectEncodingFromByteOrderMarks: false, leaveOpen: true);
            while (await listing.ReadLineAsync(token).ConfigureAwait(false) is { } line)
            {
                token.ThrowIfCancellationRequested();
                publish(line);
            }
            await data.CloseAsync(token).ConfigureAwait(false);
            if (LastReply.Code is not ("226" or "250")) throw new FtpCommandException(LastReply);
        }
    }
}
