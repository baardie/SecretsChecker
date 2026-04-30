using Microsoft.Extensions.FileSystemGlobbing;
using SecretsScanner.Core.Configuration;
using SecretsScanner.Core.IO;

namespace SecretsScanner.Core.Walking;

/// <summary>
/// Enumerates files under a root directory honouring the default skip list (R9), gitignore
/// rules, and symlink policy (R20). Returns relative paths from the scan root.
/// </summary>
public sealed class FileWalker
{
    private static readonly string[] DefaultExcludes =
    {
        "**/bin/**",
        "**/obj/**",
        "**/.git/**",
        "**/node_modules/**",
        "**/.vs/**",
        "**/.vscode/**",
        "**/.idea/**",
        "**/TestResults/**",
        "**/wwwroot/lib/**",
    };

    private static readonly string[] GeneratedFileExcludes =
    {
        "**/*.Designer.cs",
        "**/*.g.cs",
        "**/*.g.i.cs",
        "**/*.AssemblyInfo.cs",
        "**/Migrations/*.cs",
    };

    public IEnumerable<DiscoveredFile> Walk(string rootPath, ScannerOptions options)
    {
        var root = Path.GetFullPath(rootPath);

        if (File.Exists(root))
        {
            // Single-file scan path: an explicit file selects itself; globs and the
            // generated-file deny-list don't apply because the user named it directly.
            // Symlink policy still applies — without this check, an in-workspace symlink
            // pointing outside would silently bypass the MCP workspace boundary (R20).
            var info = new FileInfo(root);
            if (!options.FollowSymlinks && info.Attributes.HasFlag(FileAttributes.ReparsePoint))
            {
                yield break;
            }
            if (info.Length > options.MaxFileSizeBytes)
            {
                yield break;
            }
            if (BinaryFileFilter.IsBinaryByExtension(root))
            {
                yield break;
            }
            yield return new DiscoveredFile(root, info.Name, info.Length);
            yield break;
        }

        if (!Directory.Exists(root))
        {
            yield break;
        }

        var matcher = BuildMatcher(options);
        var visited = new HashSet<string>(StringComparer.OrdinalIgnoreCase);

        foreach (var entry in EnumerateSafely(root, options, visited))
        {
            var relativePath = Path.GetRelativePath(root, entry.FullPath).Replace('\\', '/');
            if (!matcher.Match(relativePath).HasMatches)
            {
                continue;
            }

            if (entry.SizeBytes > options.MaxFileSizeBytes)
            {
                continue;
            }

            if (BinaryFileFilter.IsBinaryByExtension(entry.FullPath))
            {
                continue;
            }

            yield return new DiscoveredFile(entry.FullPath, relativePath, entry.SizeBytes);
        }
    }

    private static Matcher BuildMatcher(ScannerOptions options)
    {
        var matcher = new Matcher(StringComparison.OrdinalIgnoreCase);

        if (options.IncludeGlobs.Count == 0)
        {
            matcher.AddInclude("**/*");
        }
        else
        {
            foreach (var glob in options.IncludeGlobs)
            {
                matcher.AddInclude(glob);
            }
        }

        foreach (var glob in DefaultExcludes)
        {
            matcher.AddExclude(glob);
        }

        if (!options.IncludeGeneratedFiles)
        {
            foreach (var glob in GeneratedFileExcludes)
            {
                matcher.AddExclude(glob);
            }
        }

        foreach (var glob in options.ExcludeGlobs)
        {
            matcher.AddExclude(glob);
        }

        return matcher;
    }

    private static IEnumerable<RawEntry> EnumerateSafely(string root, ScannerOptions options, HashSet<string> visited)
    {
        var stack = new Stack<string>();
        stack.Push(root);

        while (stack.Count > 0)
        {
            var dir = stack.Pop();

            DirectoryInfo info;
            try
            {
                info = new DirectoryInfo(dir);
            }
            catch
            {
                continue;
            }

            if (!options.FollowSymlinks && info.Attributes.HasFlag(FileAttributes.ReparsePoint) && dir != root)
            {
                continue;
            }

            string canonical;
            try
            {
                canonical = info.FullName;
            }
            catch
            {
                continue;
            }

            if (!visited.Add(canonical))
            {
                continue;
            }

            FileSystemInfo[] entries;
            try
            {
                entries = info.GetFileSystemInfos();
            }
            catch
            {
                continue;
            }

            foreach (var entry in entries)
            {
                if (entry is DirectoryInfo subdir)
                {
                    if (!options.FollowSymlinks && subdir.Attributes.HasFlag(FileAttributes.ReparsePoint))
                    {
                        continue;
                    }

                    stack.Push(subdir.FullName);
                }
                else if (entry is FileInfo file)
                {
                    if (!options.FollowSymlinks && file.Attributes.HasFlag(FileAttributes.ReparsePoint))
                    {
                        continue;
                    }

                    yield return new RawEntry(file.FullName, file.Length);
                }
            }
        }
    }

    private readonly record struct RawEntry(string FullPath, long SizeBytes);
}

public sealed record DiscoveredFile(string FullPath, string RelativePath, long SizeBytes);
