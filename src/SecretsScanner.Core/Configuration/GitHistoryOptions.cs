namespace SecretsScanner.Core.Configuration;

/// <summary>
/// Caller-supplied options for a git-history scan. Defaults match the PRD + risk-review
/// decisions: tags walked by default, dangling/reflog excluded, commit messages scanned,
/// 1,000-commit cap (Q8) — caller must set <see cref="MaxCommits"/> to <c>null</c> to lift it.
/// </summary>
public sealed record GitHistoryOptions
{
    /// <summary>
    /// Single branch to walk. <c>null</c> walks all local branches.
    /// </summary>
    public string? Branch { get; init; }

    /// <summary>
    /// Only include commits with author date at or after this instant.
    /// </summary>
    public DateTimeOffset? Since { get; init; }

    /// <summary>
    /// Maximum commits to walk (most recent first). <c>null</c> = no cap (--all-history).
    /// </summary>
    public int? MaxCommits { get; init; } = 1000;

    /// <summary>
    /// Include tag refs in the walk. Default true; <c>--no-tags</c> sets this to false.
    /// </summary>
    public bool IncludeTags { get; init; } = true;

    /// <summary>
    /// Walk dangling / unreachable commits. Default false (cost). <c>--include-unreachable</c>.
    /// </summary>
    public bool IncludeUnreachable { get; init; }

    /// <summary>
    /// Apply pattern library to commit message text (R16). Default true.
    /// </summary>
    public bool ScanCommitMessages { get; init; } = true;

    public static GitHistoryOptions Default { get; } = new();
}
