using SecretsScanner.Core.Findings;

namespace SecretsScanner.Core.Configuration;

/// <summary>
/// Caller-supplied options for a scan invocation. Defaults match the PRD + risk-review
/// decisions: PII redacted, generated files skipped, symlinks not followed, high-entropy
/// detection off.
/// </summary>
public sealed record ScannerOptions
{
    public Severity MinimumSeverity { get; init; } = Severity.Medium;
    public bool RedactPii { get; init; } = true;
    public bool IncludeHighEntropy { get; init; } = false;
    public bool IncludeGeneratedFiles { get; init; } = false;
    public bool FollowSymlinks { get; init; } = false;
    public long MaxFileSizeBytes { get; init; } = 5 * 1024 * 1024;

    /// <summary>
    /// Hard cap on the number of files the scanner will read in a single invocation. When
    /// hit, the scan returns early with <see cref="ScanResult.Truncated"/> set. Default
    /// <c>null</c> = no cap; the MCP layer sets a finite value (R5).
    /// </summary>
    public int? MaxFiles { get; init; }

    public IReadOnlyList<string> IncludeGlobs { get; init; } = Array.Empty<string>();
    public IReadOnlyList<string> ExcludeGlobs { get; init; } = Array.Empty<string>();
    public IReadOnlyList<string> AdditionalGitignoreLines { get; init; } = Array.Empty<string>();

    public static ScannerOptions Default { get; } = new();
}
