namespace SecretsScanner.Core.Walking;

/// <summary>
/// One commit visited by <see cref="GitHistoryWalker"/>. Holds enough metadata for the
/// orchestrator to build <see cref="Findings.HistoryFinding"/>s plus the per-file diff data
/// needed to filter findings down to lines actually added in this commit.
/// </summary>
internal sealed record CommitDiff(
    string CommitSha,
    DateTimeOffset CommitDate,
    string AuthorName,
    string Message,
    IReadOnlyList<string> Branches,
    IReadOnlyList<FileDiff> Files);

/// <summary>
/// One changed file in a commit. <see cref="PostCommitContent"/> is the full text of the file
/// at this commit (or empty for deletions). <see cref="AddedLineNumbers"/> are the 1-based
/// line numbers in that text that were added in this commit — only findings located on those
/// lines should be emitted, otherwise the secret was introduced in an earlier commit.
/// </summary>
internal sealed record FileDiff(
    string Path,
    string PostCommitContent,
    IReadOnlySet<int> AddedLineNumbers);
