using System.IO.Compression;
using System.Reflection.PortableExecutable;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using Microsoft.NET.HostModel.AppHost;

// Build-time utility only. The shipped EXE remains the SDK's native apphost.
return Package.Run(args);

static class Package
{
    private const string ManifestPath = "docs/dependencies.json";
    private static readonly JsonSerializerOptions Json = new()
    {
        PropertyNamingPolicy = JsonNamingPolicy.CamelCase,
        WriteIndented = true
    };
    private static readonly StringComparer Paths = StringComparer.OrdinalIgnoreCase;

    public static int Run(string[] args)
    {
        try
        {
            switch (args)
            {
                case ["organize", var source, var list, var app, var rid, var template, var readme]:
                    Organize(source, list, app, rid, template, readme);
                    break;
                case ["verify", var source]:
                    Verify(Path.GetFullPath(source));
                    break;
                case ["archive", var source, var destination]:
                    Archive(Path.GetFullPath(source), Path.GetFullPath(destination));
                    break;
                default:
                    throw new InvalidOperationException("Usage: organize <publish> <SDK file list> <assembly> <RID> <apphost template> <README> | verify <publish> | archive <publish> <zip>");
            }
            return 0;
        }
        catch (Exception error)
        {
            Console.Error.WriteLine($"Packaging failed: {error.Message}");
            return 1;
        }
    }

    private static void Organize(string source, string list, string app, string rid, string template, string readme)
    {
        source = Path.TrimEndingDirectorySeparator(Path.GetFullPath(source));
        if (Path.GetDirectoryName(source) is not { } parent || Directory.Exists(Path.Combine(source, ".git")) ||
            Directory.EnumerateFiles(source, "*.csproj").Any())
            throw new InvalidOperationException("Publish output must be a dedicated directory, not a repository or project.");
        EnsureNoLinks(source);
        var existingFiles = Files(source); // Refuse links even among stale files.
        if (app != Path.GetFileName(app) || app.Contains('.') || string.IsNullOrWhiteSpace(app))
            throw new InvalidOperationException("Invalid application assembly name.");
        if (rid is not ("win-x64" or "linux-x64"))
            throw new InvalidOperationException("Unsupported runtime identifier.");
        var executable = app + (rid == "win-x64" ? ".exe" : "");
        var sdkFiles = File.ReadAllLines(list, Encoding.UTF8).Where(p => !string.IsNullOrWhiteSpace(p))
            .Select(Relative).Distinct(StringComparer.Ordinal).Order(StringComparer.Ordinal).ToArray();
        if (sdkFiles.Distinct(Paths).Count() != sdkFiles.Length)
            throw new InvalidOperationException("Case-insensitive collision in SDK publish inventory.");
        if (existingFiles.Except(sdkFiles, Paths).Any())
        {
            // Only a previously owned distribution may contain files to clean up.
            // A mistaken PublishDir must never replace a directory of unrelated data.
            if (!File.Exists(Path.Combine(source, ManifestPath)))
                throw new InvalidOperationException("PublishDir contains unrelated files; use a dedicated output directory.");
            var previous = JsonSerializer.Deserialize<Manifest>(File.ReadAllText(RequireFile(source, ManifestPath)), Json);
            if (previous?.Schema != 1 || previous.Application != app || previous.ManagedEntryPoint != "runtime/" + app + ".dll")
                throw new InvalidOperationException("Refusing to replace an unrecognized output directory.");
            _ = RequireFile(source, previous.ManagedEntryPoint);
        }
        foreach (var required in new[] { executable, app + ".dll", app + ".deps.json", app + ".runtimeconfig.json" })
            if (!sdkFiles.Contains(required, Paths)) throw new InvalidOperationException($"SDK inventory is missing {required}.");
        foreach (var path in sdkFiles) _ = RequireFile(source, path);
        var graph = ReadGraph(source, app, sdkFiles);
        var stage = Path.Combine(parent, ".wsa-stage-" + Guid.NewGuid().ToString("N"));
        var backup = Path.Combine(parent, ".wsa-backup-" + Guid.NewGuid().ToString("N"));
        try
        {
            Directory.CreateDirectory(Path.Combine(stage, "runtime"));
            Directory.CreateDirectory(Path.Combine(stage, "docs"));
            var symbols = sdkFiles.Where(IsSymbol).ToArray();
            foreach (var path in sdkFiles.Where(p => !IsSymbol(p) && !Paths.Equals(p, executable)))
                Copy(RequireFile(source, path), Path.Combine(stage, "runtime", path));
            // HostWriter is the public SDK API also used by CreateAppHost. The DLL path
            // is relative to the EXE, never to the process's working directory.
            HostWriter.CreateAppHost(Path.GetFullPath(template), Path.Combine(stage, executable),
                "runtime/" + app + ".dll", windowsGraphicalUserInterface: rid == "win-x64",
                assemblyToCopyResourcesFrom: Path.Combine(stage, "runtime", app + ".dll"),
                dotNetSearchOptions: new() { Location = HostWriter.DotNetSearchOptions.SearchLocation.AppLocal });
            Copy(Path.GetFullPath(readme), Path.Combine(stage, "docs", "README.md"));
            var entries = Files(stage).Select(path =>
            {
                var relative = path.StartsWith("runtime/", StringComparison.Ordinal) ? path[8..] : null;
                var origins = relative is not null && graph.TryGetValue(relative, out var origin) ? origin : [];
                var category = path == executable ? "launcher" : path == "docs/README.md" ? "documentation" :
                    path.EndsWith(".deps.json", StringComparison.Ordinal) || path.EndsWith(".runtimeconfig.json", StringComparison.Ordinal)
                        ? "runtime-metadata" : origins.Select(o => o.Category).Distinct().SingleOrDefault() ?? "content";
                var file = Path.Combine(stage, path);
                return new Entry(path, new FileInfo(file).Length, Hash(file), category, Kind(file),
                    origins.Select(o => o.Library).Distinct().Order(StringComparer.Ordinal).ToArray());
            }).ToArray();
            using var config = JsonDocument.Parse(File.ReadAllText(RequireFile(source, app + ".runtimeconfig.json")));
            var options = config.RootElement.GetProperty("runtimeOptions");
            if (!options.TryGetProperty("includedFrameworks", out _))
                throw new InvalidOperationException("The runtimeconfig is not self-contained.");
            var version = System.Diagnostics.FileVersionInfo.GetVersionInfo(Path.Combine(stage, "runtime", app + ".dll")).ProductVersion ?? "unknown";
            var manifest = new Manifest(1, app, version, rid, true, executable, "runtime/" + app + ".dll", symbols, entries);
            File.WriteAllText(Path.Combine(stage, ManifestPath), JsonSerializer.Serialize(manifest, Json) + "\n", new UTF8Encoding(false));
            Verify(stage);
            Directory.Move(source, backup);
            try { Directory.Move(stage, source); }
            catch { Directory.Move(backup, source); throw; }
            Directory.Delete(backup, recursive: true);
            Console.WriteLine($"Organized publish: {source}; root DLLs: 0; symbols excluded: {symbols.Length}.");
        }
        finally
        {
            if (Directory.Exists(stage)) Directory.Delete(stage, recursive: true);
        }
    }

    private static Manifest Verify(string source)
    {
        EnsureNoLinks(source);
        var manifest = JsonSerializer.Deserialize<Manifest>(File.ReadAllText(RequireFile(source, ManifestPath)), Json)
            ?? throw new InvalidOperationException("Empty dependency manifest.");
        if (manifest.Schema != 1 || !manifest.SelfContained || manifest.RuntimeIdentifier is not ("win-x64" or "linux-x64"))
            throw new InvalidOperationException("Unsupported deployment manifest.");
        if (manifest.EntryPoint != manifest.Application + (manifest.RuntimeIdentifier == "win-x64" ? ".exe" : "") ||
            manifest.ManagedEntryPoint != "runtime/" + manifest.Application + ".dll")
            throw new InvalidOperationException("Unexpected entry point.");
        var listed = manifest.Files.Select(e => Relative(e.Path)).Append(ManifestPath).ToArray();
        if (listed.Distinct(Paths).Count() != listed.Length || listed.Any(IsSymbol))
            throw new InvalidOperationException("Duplicate paths or debug symbols in distribution.");
        if (!Files(source).ToHashSet(Paths).SetEquals(listed))
            throw new InvalidOperationException("Distribution contains missing or unexpected files.");
        foreach (var entry in manifest.Files)
        {
            var path = RequireFile(source, entry.Path);
            if (new FileInfo(path).Length != entry.Bytes || Hash(path) != entry.Sha256 || Kind(path) != entry.Kind ||
                string.IsNullOrWhiteSpace(entry.Category))
                throw new InvalidOperationException($"Content/metadata mismatch: {entry.Path}");
            if (!entry.Path.StartsWith("runtime/", StringComparison.Ordinal) && entry.Path != manifest.EntryPoint && entry.Path != "docs/README.md")
                throw new InvalidOperationException($"Unexpected root content: {entry.Path}");
        }
        var payload = manifest.Files.Where(e => e.Path.StartsWith("runtime/", StringComparison.Ordinal)).Select(e => e.Path[8..]).ToArray();
        var runtime = Path.Combine(source, "runtime");
        var graph = ReadGraph(runtime, manifest.Application, payload);
        foreach (var entry in manifest.Files.Where(e => e.Path.StartsWith("runtime/", StringComparison.Ordinal)))
            if (graph.TryGetValue(entry.Path[8..], out var origins) &&
                !entry.Origins.ToHashSet(StringComparer.Ordinal).SetEquals(origins.Select(o => o.Library)))
                throw new InvalidOperationException($"Dependency provenance mismatch: {entry.Path}");
        using var config = JsonDocument.Parse(File.ReadAllText(RequireFile(runtime, manifest.Application + ".runtimeconfig.json")));
        if (!config.RootElement.GetProperty("runtimeOptions").TryGetProperty("includedFrameworks", out _))
            throw new InvalidOperationException("Expected a self-contained runtimeconfig.");
        foreach (var name in manifest.RuntimeIdentifier == "win-x64"
                     ? new[] { "hostfxr.dll", "hostpolicy.dll", "coreclr.dll", "System.Private.CoreLib.dll" }
                     : ["libhostfxr.so", "libhostpolicy.so", "libcoreclr.so", "System.Private.CoreLib.dll"])
            _ = RequireFile(runtime, name);
        var hostBytes = File.ReadAllBytes(RequireFile(source, manifest.EntryPoint));
        if (hostBytes.AsSpan().IndexOf(Encoding.UTF8.GetBytes(manifest.ManagedEntryPoint + "\0")) < 0)
            throw new InvalidOperationException("Apphost does not point to the packaged managed entry point.");
        if (manifest.RuntimeIdentifier == "win-x64")
        {
            using var pe = new PEReader(new MemoryStream(hostBytes));
            if (pe.PEHeaders.CoffHeader.Machine != Machine.Amd64 || pe.PEHeaders.PEHeader?.Subsystem != Subsystem.WindowsGui)
                throw new InvalidOperationException("Expected the Windows x64 GUI apphost.");
        }
        Console.WriteLine($"Distribution verified: {manifest.Files.Length + 1} files, {manifest.Files.Sum(e => e.Bytes):N0} inventoried bytes.");
        return manifest;
    }

    private static Dictionary<string, List<Origin>> ReadGraph(string source, string app, string[] files)
    {
        using var deps = JsonDocument.Parse(File.ReadAllText(RequireFile(source, app + ".deps.json")));
        var root = deps.RootElement;
        var target = root.GetProperty("targets").GetProperty(root.GetProperty("runtimeTarget").GetProperty("name").GetString()!);
        var result = new Dictionary<string, List<Origin>>(Paths);
        foreach (var library in target.EnumerateObject())
        {
            var type = root.GetProperty("libraries").GetProperty(library.Name).GetProperty("type").GetString();
            var origin = new Origin(library.Name, Category(library.Name.Split('/')[0], type));
            foreach (var group in new[] { "runtime", "native", "resources" })
            {
                if (!library.Value.TryGetProperty(group, out var assets)) continue;
                foreach (var asset in assets.EnumerateObject())
                {
                    var key = Relative(asset.Name);
                    // Native NuGet PDBs are symbols, not loadable runtime dependencies.
                    // Retain their declaration in the original SDK deps file unchanged.
                    if (IsSymbol(key)) continue;
                    var expected = group == "resources" && asset.Value.TryGetProperty("locale", out var locale)
                        ? Relative(locale.GetString()! + "/" + Path.GetFileName(key)) : Path.GetFileName(key);
                    var matches = files.Where(p => Paths.Equals(p, key)).ToArray();
                    if (matches.Length == 0) matches = files.Where(p => Paths.Equals(p, expected)).ToArray();
                    if (matches.Length != 1)
                        throw new InvalidOperationException($"Dependency missing or ambiguous: {library.Name}: {asset.Name}");
                    _ = RequireFile(source, matches[0]);
                    if (!result.TryGetValue(matches[0], out var origins)) result[matches[0]] = origins = [];
                    if (!origins.Contains(origin)) origins.Add(origin);
                }
            }
        }
        return result;
    }

    private static string Category(string package, string? type) => type switch
    {
        "runtimepack" => "dotnet-runtime",
        "project" => "application",
        _ when package.StartsWith("Avalonia", StringComparison.Ordinal) || package.StartsWith("ScottPlot", StringComparison.Ordinal) ||
            package is "SkiaSharp" or "SkiaSharp.NativeAssets.Win32" or "SkiaSharp.NativeAssets.Linux" or "HarfBuzzSharp" or
                "HarfBuzzSharp.NativeAssets.Win32" or "HarfBuzzSharp.NativeAssets.Linux" or "MicroCom.Runtime" or
                "CommunityToolkit.Mvvm" or "Tmds.DBus.Protocol" => "ui",
        _ when package is "AngleSharp" => "networking",
        _ when package is "Serilog" or "Serilog.Sinks.File" or "Microsoft.Extensions.DependencyInjection" or
            "Microsoft.Extensions.DependencyInjection.Abstractions" => "diagnostics-and-di",
        _ => "third-party"
    };

    private static void Archive(string source, string destination)
    {
        Verify(source);
        EnsureNoLinks(Path.GetDirectoryName(destination)!);
        if (Path.GetRelativePath(source, destination).Split(Path.DirectorySeparatorChar)[0] != "..")
            throw new InvalidOperationException("ZIP must be outside the distribution directory.");
        EnsureNoLinks(destination);
        EnsureNoLinks(destination + ".sha256");
        var temporary = destination + ".tmp-" + Guid.NewGuid().ToString("N");
        try
        {
            using (var output = ZipFile.Open(temporary, ZipArchiveMode.Create))
                foreach (var path in Files(source))
                {
                    var entry = output.CreateEntry(Path.GetFileName(Path.TrimEndingDirectorySeparator(source)) + "/" + path, CompressionLevel.Optimal);
                    entry.LastWriteTime = new DateTimeOffset(2000, 1, 1, 0, 0, 0, TimeSpan.Zero);
                    using var input = File.OpenRead(RequireFile(source, path));
                    using var target = entry.Open();
                    input.CopyTo(target);
                }
            using (var zip = ZipFile.OpenRead(temporary))
            {
                foreach (var entry in zip.Entries)
                {
                    var path = Relative(entry.FullName[(entry.FullName.IndexOf('/') + 1)..]);
                    using var content = entry.Open();
                    if (Convert.ToHexStringLower(SHA256.HashData(content)) != Hash(RequireFile(source, path)))
                        throw new InvalidOperationException($"ZIP integrity mismatch: {path}");
                }
            }
            File.Move(temporary, destination, overwrite: true);
            var checksum = Hash(destination) + "  " + Path.GetFileName(destination) + "\n";
            File.WriteAllText(destination + ".sha256", checksum, new UTF8Encoding(false));
            Console.WriteLine($"Archive: {destination} ({new FileInfo(destination).Length:N0} bytes); SHA-256: {checksum.Trim()}");
        }
        finally { if (File.Exists(temporary)) File.Delete(temporary); }
    }

    private static string Relative(string path)
    {
        path = path.Replace('\\', '/');
        if (string.IsNullOrWhiteSpace(path) || path.StartsWith('/') || path.Contains(':') ||
            path.Split('/').Any(p => p is "" or "." or ".." || p.Any(char.IsControl) || p.EndsWith(' ') || p.EndsWith('.')))
            throw new InvalidOperationException($"Unsafe relative path: {path}");
        return path;
    }

    private static void EnsureNoLinks(string path)
    {
        for (var part = Path.GetFullPath(path); part is not null; part = Path.GetDirectoryName(part))
        {
            FileAttributes attributes;
            try { attributes = File.GetAttributes(part); }
            catch (FileNotFoundException) { continue; }
            catch (DirectoryNotFoundException) { continue; }
            if ((attributes & FileAttributes.ReparsePoint) != 0)
                throw new InvalidOperationException($"Symbolic links/reparse points are forbidden: {part}");
        }
    }

    private static string RequireFile(string root, string relative)
    {
        var path = Path.Combine(root, Relative(relative));
        EnsureNoLinks(path);
        if (!File.Exists(path)) throw new FileNotFoundException("Required distribution file is missing.", relative);
        return path;
    }

    private static string[] Files(string root)
    {
        var result = new List<string>();
        Visit(root);
        return result.Order(StringComparer.Ordinal).ToArray();
        void Visit(string directory)
        {
            foreach (var path in Directory.EnumerateFileSystemEntries(directory))
            {
                if ((File.GetAttributes(path) & FileAttributes.ReparsePoint) != 0)
                    throw new InvalidOperationException($"Symbolic links/reparse points are forbidden: {path}");
                if (Directory.Exists(path)) Visit(path);
                else result.Add(Relative(Path.GetRelativePath(root, path)));
            }
        }
    }

    private static void Copy(string source, string destination)
    {
        EnsureNoLinks(source);
        Directory.CreateDirectory(Path.GetDirectoryName(destination)!);
        File.Copy(source, destination);
    }

    private static bool IsSymbol(string path) => path.EndsWith(".pdb", StringComparison.OrdinalIgnoreCase);
    private static string Hash(string path)
    {
        using var input = File.OpenRead(path);
        return Convert.ToHexStringLower(SHA256.HashData(input));
    }
    private static string Kind(string path)
    {
        if (path.EndsWith(".dll", StringComparison.OrdinalIgnoreCase) || path.EndsWith(".exe", StringComparison.OrdinalIgnoreCase))
        {
            using var input = File.OpenRead(path);
            using var pe = new PEReader(input);
            return pe.HasMetadata ? "managed" : "native";
        }
        using (var input = File.OpenRead(path))
        {
            Span<byte> magic = stackalloc byte[4];
            if (input.Read(magic) == 4 && magic.SequenceEqual(new byte[] { 0x7f, (byte)'E', (byte)'L', (byte)'F' })) return "native";
        }
        return "data";
    }

    private sealed record Origin(string Library, string Category);
    private sealed record Entry(string Path, long Bytes, string Sha256, string Category, string Kind, string[] Origins);
    private sealed record Manifest(int Schema, string Application, string Version, string RuntimeIdentifier,
        bool SelfContained, string EntryPoint, string ManagedEntryPoint, string[] ExcludedSymbols, Entry[] Files);
}
