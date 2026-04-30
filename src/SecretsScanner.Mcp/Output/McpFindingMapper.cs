using SecretsScanner.Core.Findings;

namespace SecretsScanner.Mcp.Output;

/// <summary>
/// MCP-side projection of a sanitised <see cref="Finding"/> into the wire shape Claude sees.
/// Two privacy guarantees are enforced here in addition to whatever the core sanitiser
/// already did:
///
///   • <b>R1 — entropy stripped.</b> Claude has no use for the heuristic precision signal,
///     and emitting it leaks bits about the underlying value.
///   • <b>R8 — author identity stripped.</b> Even though core redaction replaces author
///     name with <c>[redacted]</c>, the MCP wire shape drops the field entirely so neither a
///     stale token nor a leaky log line can reintroduce it.
///
/// File paths still pass through <see cref="Redaction"/> at the core boundary, which already
/// rewrites user-home paths to <c>~</c>. The MCP transport must not reverse that.
/// </summary>
public static class McpFindingMapper
{
    public static object Map(Finding f) => f switch
    {
        HistoryFinding h => new McpHistoryFinding
        {
            Source = h.Source.ToWireString(),
            File = h.File,
            Line = h.Line,
            Column = h.Column,
            SecretType = h.SecretType,
            Severity = h.Severity.ToWireString(),
            Hint = h.Hint,
            SuggestedFix = h.SuggestedFix,
            CommitSha = h.CommitSha,
            CommitShort = h.CommitShort,
            CommitDate = h.CommitDate,
            Branches = h.Branches,
            StillPresent = h.StillPresent,
        },
        CommitMessageFinding c => new McpCommitMessageFinding
        {
            Source = c.Source.ToWireString(),
            File = c.File,
            Line = c.Line,
            Column = c.Column,
            SecretType = c.SecretType,
            Severity = c.Severity.ToWireString(),
            Hint = c.Hint,
            SuggestedFix = c.SuggestedFix,
            CommitSha = c.CommitSha,
            CommitShort = c.CommitShort,
            CommitDate = c.CommitDate,
        },
        Finding when f.GetType() == typeof(Finding) => new McpWorkingTreeFinding
        {
            Source = f.Source.ToWireString(),
            File = f.File,
            Line = f.Line,
            Column = f.Column,
            SecretType = f.SecretType,
            Severity = f.Severity.ToWireString(),
            Hint = f.Hint,
            SuggestedFix = f.SuggestedFix,
        },
        _ => throw new InvalidOperationException(
            $"Unhandled Finding subtype '{f.GetType().Name}' — McpFindingMapper must be updated when a new subtype is added."),
    };

    public static IReadOnlyList<object> MapAll(IEnumerable<Finding> findings)
        => findings.Select(Map).ToList();
}

/// <summary>Wire shape for a working-tree finding. Same as the JSON wire shape minus entropy.</summary>
public sealed record McpWorkingTreeFinding
{
    public required string Source { get; init; }
    public required string File { get; init; }
    public required int Line { get; init; }
    public required int Column { get; init; }
    public required string SecretType { get; init; }
    public required string Severity { get; init; }
    public required string Hint { get; init; }
    public required string SuggestedFix { get; init; }
}

/// <summary>Wire shape for a history finding. No <c>entropy</c>, no <c>authorName</c>.</summary>
public sealed record McpHistoryFinding
{
    public required string Source { get; init; }
    public required string File { get; init; }
    public required int Line { get; init; }
    public required int Column { get; init; }
    public required string SecretType { get; init; }
    public required string Severity { get; init; }
    public required string Hint { get; init; }
    public required string SuggestedFix { get; init; }
    public required string CommitSha { get; init; }
    public required string CommitShort { get; init; }
    public required DateTimeOffset CommitDate { get; init; }
    public required IReadOnlyList<string> Branches { get; init; }
    public required bool StillPresent { get; init; }
}

/// <summary>Wire shape for a commit-message finding. No <c>entropy</c>, no <c>authorName</c>.</summary>
public sealed record McpCommitMessageFinding
{
    public required string Source { get; init; }
    public required string File { get; init; }
    public required int Line { get; init; }
    public required int Column { get; init; }
    public required string SecretType { get; init; }
    public required string Severity { get; init; }
    public required string Hint { get; init; }
    public required string SuggestedFix { get; init; }
    public required string CommitSha { get; init; }
    public required string CommitShort { get; init; }
    public required DateTimeOffset CommitDate { get; init; }
}
