namespace SecretsScanner.Cli.Hooks;

/// <summary>
/// Installs / appends / uninstalls the pre-commit hook (R11). Strategy:
///   1. Detect known hook managers (Husky, lefthook, pre-commit-fw) by repo markers and emit
///      paste-ready instructions instead of touching their config files.
///   2. If no hook exists, write a fresh one.
///   3. If an unknown hook exists, refuse by default; <c>--force</c> overwrites with backup,
///      <c>--append</c> adds inside a marker block.
///   4. <c>--uninstall-hook</c> removes the marker block (or the whole file if it's solely
///      ours).
/// </summary>
public sealed class PreCommitHookInstaller
{
    private const string MarkerStart = "# >>> dotnet-tool-secrets-scan >>>";
    private const string MarkerEnd = "# <<< dotnet-tool-secrets-scan <<<";
    private const string Command = "dotnet tool-secrets-scan --severity high";

    private readonly string _repoRoot;

    public PreCommitHookInstaller(string repoRoot)
    {
        _repoRoot = repoRoot;
    }

    public InstallResult Install(InstallMode mode)
    {
        var manager = DetectKnownManager(_repoRoot);
        if (manager is { } known)
        {
            return new InstallResult(InstallOutcome.DelegatedToKnownManager, known, GuidanceFor(known));
        }

        var hookPath = Path.Combine(_repoRoot, ".git", "hooks", "pre-commit");
        if (!Directory.Exists(Path.Combine(_repoRoot, ".git")))
        {
            return new InstallResult(InstallOutcome.NotAGitRepo, null, ".git directory not found at the supplied repo root");
        }

        Directory.CreateDirectory(Path.GetDirectoryName(hookPath)!);

        if (!File.Exists(hookPath))
        {
            WriteFreshHook(hookPath);
            return new InstallResult(InstallOutcome.WroteFresh, null, $"wrote {hookPath}");
        }

        var existing = File.ReadAllText(hookPath);

        if (existing.Contains(MarkerStart))
        {
            return new InstallResult(InstallOutcome.AlreadyInstalled, null, "marker block already present");
        }

        return mode switch
        {
            InstallMode.Refuse => new InstallResult(
                InstallOutcome.RefusedExistingHook,
                null,
                "an unknown pre-commit hook exists; rerun with --append to add inside a marker block, or --force to overwrite (backup will be written)."),
            InstallMode.Append => DoAppend(hookPath, existing),
            InstallMode.Force => DoForce(hookPath, existing),
            _ => throw new ArgumentOutOfRangeException(nameof(mode)),
        };
    }

    public InstallResult Uninstall()
    {
        var hookPath = Path.Combine(_repoRoot, ".git", "hooks", "pre-commit");
        if (!File.Exists(hookPath))
        {
            return new InstallResult(InstallOutcome.NotInstalled, null, "no pre-commit hook present");
        }

        var content = File.ReadAllText(hookPath);
        if (!content.Contains(MarkerStart))
        {
            return new InstallResult(InstallOutcome.NotInstalled, null, "no marker block found");
        }

        var stripped = StripMarkerBlock(content);
        if (string.IsNullOrWhiteSpace(stripped) || stripped.Trim() == "#!/bin/sh")
        {
            File.Delete(hookPath);
            return new InstallResult(InstallOutcome.RemovedFile, null, $"removed {hookPath}");
        }

        File.WriteAllText(hookPath, stripped);
        return new InstallResult(InstallOutcome.RemovedMarkerBlock, null, "removed marker block, kept other hook content");
    }

    public static KnownHookManager? DetectKnownManager(string repoRoot)
    {
        if (File.Exists(Path.Combine(repoRoot, "lefthook.yml")) ||
            File.Exists(Path.Combine(repoRoot, "lefthook.yaml")))
        {
            return KnownHookManager.Lefthook;
        }

        if (File.Exists(Path.Combine(repoRoot, ".pre-commit-config.yaml")))
        {
            return KnownHookManager.PreCommitFramework;
        }

        var packageJson = Path.Combine(repoRoot, "package.json");
        if (File.Exists(packageJson) &&
            File.ReadAllText(packageJson).Contains("\"husky\"", StringComparison.OrdinalIgnoreCase))
        {
            return KnownHookManager.Husky;
        }

        if (Directory.Exists(Path.Combine(repoRoot, ".husky")))
        {
            return KnownHookManager.Husky;
        }

        return null;
    }

    public static string GuidanceFor(KnownHookManager manager) => manager switch
    {
        KnownHookManager.Husky =>
            "Husky detected. Add this to .husky/pre-commit:\n" +
            $"#!/usr/bin/env sh\n. \"$(dirname -- \"$0\")/_/husky.sh\"\n{Command}\n",
        KnownHookManager.Lefthook =>
            "lefthook detected. Add this to lefthook.yml:\n" +
            "pre-commit:\n  commands:\n    secrets-scan:\n      run: " + Command + "\n",
        KnownHookManager.PreCommitFramework =>
            "pre-commit framework detected. Add a local hook in .pre-commit-config.yaml:\n" +
            "repos:\n  - repo: local\n    hooks:\n      - id: secrets-scan\n        name: dotnet-tool-secrets-scan\n        entry: " + Command + "\n        language: system\n",
        _ => string.Empty,
    };

    private static void WriteFreshHook(string path)
    {
        var script = $"""
        #!/bin/sh
        {MarkerStart}
        {Command} || exit 1
        {MarkerEnd}
        """;
        File.WriteAllText(path, script + "\n");
        TryMakeExecutable(path);
    }

    private static InstallResult DoAppend(string hookPath, string existing)
    {
        var separator = existing.EndsWith('\n') ? string.Empty : "\n";
        var appended = existing + separator + MarkerStart + "\n" + Command + " || exit 1\n" + MarkerEnd + "\n";
        File.WriteAllText(hookPath, appended);
        TryMakeExecutable(hookPath);
        return new InstallResult(InstallOutcome.AppendedToExisting, null, $"appended marker block to {hookPath}");
    }

    private static InstallResult DoForce(string hookPath, string existing)
    {
        var backupPath = hookPath + ".bak";
        File.WriteAllText(backupPath, existing);
        WriteFreshHook(hookPath);
        return new InstallResult(InstallOutcome.OverwroteWithBackup, null, $"existing hook backed up to {backupPath}");
    }

    private static string StripMarkerBlock(string content)
    {
        var startIdx = content.IndexOf(MarkerStart, StringComparison.Ordinal);
        if (startIdx < 0)
        {
            return content;
        }

        var endIdx = content.IndexOf(MarkerEnd, startIdx, StringComparison.Ordinal);
        if (endIdx < 0)
        {
            return content;
        }

        endIdx += MarkerEnd.Length;
        if (endIdx < content.Length && content[endIdx] == '\n')
        {
            endIdx++;
        }

        return content.Remove(startIdx, endIdx - startIdx);
    }

    private static void TryMakeExecutable(string path)
    {
        if (OperatingSystem.IsWindows())
        {
            return;
        }

        try
        {
            File.SetUnixFileMode(path,
                UnixFileMode.UserRead | UnixFileMode.UserWrite | UnixFileMode.UserExecute |
                UnixFileMode.GroupRead | UnixFileMode.GroupExecute |
                UnixFileMode.OtherRead | UnixFileMode.OtherExecute);
        }
        catch
        {
            // best effort; on filesystems that don't support modes (e.g. exFAT) just skip.
        }
    }
}

public enum InstallMode
{
    Refuse,
    Append,
    Force,
}

public enum InstallOutcome
{
    WroteFresh,
    AppendedToExisting,
    OverwroteWithBackup,
    RefusedExistingHook,
    AlreadyInstalled,
    DelegatedToKnownManager,
    NotAGitRepo,
    NotInstalled,
    RemovedMarkerBlock,
    RemovedFile,
}

public enum KnownHookManager
{
    Husky,
    Lefthook,
    PreCommitFramework,
}

public sealed record InstallResult(InstallOutcome Outcome, KnownHookManager? Manager, string Message);
