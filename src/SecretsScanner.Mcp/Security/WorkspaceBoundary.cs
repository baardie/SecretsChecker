namespace SecretsScanner.Mcp.Security;

/// <summary>
/// R5 — three-layer path-scope enforcement for the MCP server.
///
///   1. <b>Workspace root resolution</b>. Read from <c>CLAUDE_PROJECT_DIR</c> if the host set
///      it, otherwise the cwd of this process. Cached at construction.
///   2. <b>Path containment</b>. Every requested <c>path</c> is canonicalised via
///      <see cref="Path.GetFullPath(string)"/> and verified to be a descendant of the
///      workspace root. Off-workspace requests are rejected unless the caller passes
///      <c>allowOutsideWorkspace = true</c>.
///   3. <b>System-path denylist</b>. Even with the override on, a fixed denylist of obvious
///      attack surfaces is refused: <c>/</c>, <c>/etc</c>, <c>/var</c>, <c>/usr</c>, drive
///      roots like <c>C:\</c>, <c>C:\Windows</c>, <c>C:\Program Files</c>, and any
///      <c>C:\Users\&lt;other&gt;</c> directory. The current user's own home stays usable.
/// </summary>
public sealed class WorkspaceBoundary
{
    public const string WorkspaceEnvVar = "CLAUDE_PROJECT_DIR";

    private static readonly string[] PosixDeniedRoots =
        { "/", "/etc", "/var", "/usr", "/bin", "/sbin", "/boot", "/sys", "/proc" };

    private static readonly string[] WindowsDeniedRoots =
        { @"C:\Windows", @"C:\Program Files", @"C:\Program Files (x86)", @"C:\ProgramData" };

    public string Root { get; }

    public WorkspaceBoundary(string root)
    {
        Root = NormaliseDirectory(Path.GetFullPath(root));
    }

    /// <summary>
    /// Resolves the workspace root from <c>CLAUDE_PROJECT_DIR</c>, then current directory.
    /// </summary>
    public static WorkspaceBoundary Resolve()
    {
        var fromEnv = Environment.GetEnvironmentVariable(WorkspaceEnvVar);
        var root = !string.IsNullOrWhiteSpace(fromEnv) ? fromEnv : Directory.GetCurrentDirectory();
        return new WorkspaceBoundary(root);
    }

    /// <summary>
    /// Canonicalises and validates <paramref name="path"/>. Returns the canonical absolute
    /// path on allow; structured rejection reasons on deny.
    /// </summary>
    public PathDecision Validate(string path, bool allowOutsideWorkspace = false)
    {
        if (string.IsNullOrWhiteSpace(path))
        {
            return PathDecision.Deny("path is empty", string.Empty);
        }

        string canonical;
        try
        {
            canonical = Path.GetFullPath(path);
        }
        catch (Exception)
        {
            return PathDecision.Deny("path could not be canonicalised", path);
        }

        if (IsSystemPath(canonical))
        {
            return PathDecision.Deny("path is on the system denylist", canonical);
        }

        if (!allowOutsideWorkspace && !IsWithinWorkspace(canonical))
        {
            return PathDecision.Deny(
                $"path is outside workspace ({Root}); set allowOutsideWorkspace to override",
                canonical);
        }

        return PathDecision.Allow(canonical);
    }

    private bool IsWithinWorkspace(string canonical)
    {
        var normalised = NormaliseDirectory(canonical);
        if (normalised.Equals(Root, StringComparison.OrdinalIgnoreCase))
        {
            return true;
        }

        var rootWithSeparator = Root.EndsWith(Path.DirectorySeparatorChar)
            ? Root
            : Root + Path.DirectorySeparatorChar;
        return normalised.StartsWith(rootWithSeparator, StringComparison.OrdinalIgnoreCase);
    }

    private static bool IsSystemPath(string canonical)
    {
        if (OperatingSystem.IsWindows())
        {
            // Drive root on its own, e.g. "C:\".
            if (canonical.Length == 3 && char.IsLetter(canonical[0]) && canonical[1] == ':' && canonical[2] == '\\')
            {
                return true;
            }

            foreach (var denied in WindowsDeniedRoots)
            {
                if (StartsWithDir(canonical, denied))
                {
                    return true;
                }
            }

            // C:\Users\<other-user>: anything under \Users that isn't the current user's home.
            if (StartsWithDir(canonical, @"C:\Users"))
            {
                var home = Environment.GetEnvironmentVariable("USERPROFILE")
                    ?? Environment.GetFolderPath(Environment.SpecialFolder.UserProfile);
                if (!string.IsNullOrEmpty(home) && !StartsWithDir(canonical, home))
                {
                    return true;
                }
            }

            return false;
        }

        // POSIX: paths under the user's HOME or the system per-user temp directory are
        // never on the deny list, even if they happen to live under one of the denied roots.
        // This matters on macOS in particular, where Path.GetTempPath() returns
        // /var/folders/<id>/T/... — under the /var deny entry but a legitimate user area.
        var posixHome = Environment.GetEnvironmentVariable("HOME")
            ?? Environment.GetFolderPath(Environment.SpecialFolder.UserProfile);
        if (!string.IsNullOrEmpty(posixHome) && StartsWithDir(canonical, posixHome))
        {
            return false;
        }

        var tempPrefix = Path.GetTempPath();
        if (!string.IsNullOrEmpty(tempPrefix) && StartsWithDir(canonical, tempPrefix))
        {
            return false;
        }

        foreach (var denied in PosixDeniedRoots)
        {
            if (canonical.Equals(denied, StringComparison.Ordinal))
            {
                return true;
            }

            // "/" only matches exactly; without this guard, StartsWithDir(candidate, "/")
            // matches every absolute path on POSIX and the boundary denies everything.
            if (denied == "/")
            {
                continue;
            }

            if (StartsWithDir(canonical, denied))
            {
                return true;
            }
        }

        return false;
    }

    private static bool StartsWithDir(string candidate, string prefix)
    {
        if (string.IsNullOrEmpty(prefix))
        {
            return false;
        }

        var normalised = NormaliseDirectory(prefix);
        if (candidate.Equals(normalised, StringComparison.OrdinalIgnoreCase))
        {
            return true;
        }

        var withSep = normalised.EndsWith(Path.DirectorySeparatorChar)
            ? normalised
            : normalised + Path.DirectorySeparatorChar;
        return candidate.StartsWith(withSep, StringComparison.OrdinalIgnoreCase);
    }

    private static string NormaliseDirectory(string path)
        => path.Length > 1 ? path.TrimEnd(Path.DirectorySeparatorChar) : path;
}

/// <summary>
/// Outcome of <see cref="WorkspaceBoundary.Validate"/>. <see cref="CanonicalPath"/> is the
/// post-normalisation absolute path on allow; on deny it's whatever the caller supplied
/// before the rejection, for diagnostic purposes.
/// </summary>
public sealed record PathDecision(bool Allowed, string? Reason, string CanonicalPath)
{
    public static PathDecision Allow(string canonicalPath) => new(true, null, canonicalPath);
    public static PathDecision Deny(string reason, string path) => new(false, reason, path);
}
