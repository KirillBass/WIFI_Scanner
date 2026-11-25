using System.Net;
using WirelessSecurityAnalyzer.Core.Models;

namespace WirelessSecurityAnalyzer.Core.NetworkAudit;

public enum ResourceEntryKind { File, Folder, Link }
public enum ResourceAccess { Granted, AuthenticationRequired, Denied, SecureConnectionRequired, Unavailable, Unsupported }
public enum CatalogState { Complete, Partial, Failed }

public sealed record ResourceEntry(string Name, string RemotePath, ResourceEntryKind Kind, long? SizeBytes,
    DateTimeOffset? CreatedAt, DateTimeOffset? ModifiedAt)
{
    public string Extension => Kind == ResourceEntryKind.File ? Path.GetExtension(Name) : "";
    public string KindText => Kind switch { ResourceEntryKind.Folder => "Папка", ResourceEntryKind.Link => "Ссылка", _ => "Файл" };
    public string SizeText => SizeBytes?.ToString("N0") ?? "-";
    public string ModifiedText => ModifiedAt?.ToLocalTime().ToString("dd.MM.yyyy HH:mm") ?? "-";
    public string AccessText => Kind == ResourceEntryKind.Link ? "Переход отключён" : "Видим в каталоге";
}

public sealed record CatalogResult(ResourceAccess Access, CatalogState State, string Path, string Message)
{
    public string Root { get; init; } = "";
}

public interface IResourceCatalogReader
{
    string Protocol { get; }

    Task<CatalogResult> ReadAsync(LocalNetworkInfo network, AuditRow endpoint, string resourceRoot,
        IReadOnlyList<string> folders, NetworkCredential? credential, Action<ResourceEntry> publish, CancellationToken token);
}

public static class ResourcePath
{
    public static bool IsSegment(string name) => name.Length > 0 && name is not ("." or "..") &&
        name.All(c => c is not ('/' or '\\') && !char.IsControl(c));

    public static bool IsWindowsSegment(string name) => IsSegment(name) && !name.EndsWith(' ') && !name.EndsWith('.') &&
        !name.Any(c => c is '<' or '>' or ':' or '"' or '|' or '?' or '*') && !Path.IsPathFullyQualified(name);

    public static string SmbShare(string address, string unc)
    {
        var prefix = $"\\\\{address}\\";
        if (!unc.StartsWith(prefix, StringComparison.Ordinal)) return "";
        var name = unc[prefix.Length..].TrimEnd('\\');
        return IsWindowsSegment(name) && !name.EndsWith('$') && !Path.IsPathFullyQualified(name) ? name : "";
    }
}
