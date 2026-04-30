namespace SecretsScanner.Core.Findings;

/// <summary>
/// Finding raised against a commit message body rather than a file. <see cref="Finding.File"/>
/// carries the literal token <c>"&lt;commit-message&gt;"</c>; <see cref="Finding.Line"/> and
/// <see cref="Finding.Column"/> are the position within the message text.
/// </summary>
public sealed record CommitMessageFinding : Finding
{
    public required string CommitSha { get; init; }
    public required string CommitShort { get; init; }
    public required DateTimeOffset CommitDate { get; init; }
    public required string AuthorName { get; init; }
}
