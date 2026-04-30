namespace SecretsScanner.Core.Findings;

/// <summary>
/// History-scan finding. Extends <see cref="Finding"/> with commit metadata. Per R8, PII fields
/// (author name, paths under user home) are subject to redaction at output time and are absent
/// from MCP responses regardless of configuration.
/// </summary>
public sealed record HistoryFinding : Finding
{
    public required string CommitSha { get; init; }
    public required string CommitShort { get; init; }
    public required DateTimeOffset CommitDate { get; init; }
    public required string AuthorName { get; init; }
    public required IReadOnlyList<string> Branches { get; init; }
    public required bool StillPresent { get; init; }
}
