using SecretsScanner.Cli.Output;
using SecretsScanner.Core.Configuration;
using SecretsScanner.Core.Findings;

namespace SecretsScanner.Cli.Configuration;

/// <summary>
/// CLI-side options POCO. Bound from layered config files via <see cref="ConfigLoader"/> and
/// then overridden by CLI flags. Translated into <see cref="ScannerOptions"/> when the scan
/// runs.
/// </summary>
public sealed record CliOptions
{
    public string Path { get; init; } = "./";
    public OutputFormat Format { get; init; } = OutputFormat.Console;
    public Severity Severity { get; init; } = Severity.Medium;
    public string? Baseline { get; init; }
    public string? WriteBaseline { get; init; }
    public bool Watch { get; init; }
    public bool InstallHook { get; init; }
    public bool UninstallHook { get; init; }
    public bool ForceHook { get; init; }
    public bool AppendHook { get; init; }
    public string? Output { get; init; }
    public bool IncludePii { get; init; }
    public bool IncludeGenerated { get; init; }
    public bool IncludeHighEntropy { get; init; }
    public bool FollowSymlinks { get; init; }
    public long? MaxFileSizeBytes { get; init; }
    public ColorMode Color { get; init; } = ColorMode.Auto;
    public IReadOnlyList<string> Exclude { get; init; } = Array.Empty<string>();
    public IReadOnlyList<string> Include { get; init; } = Array.Empty<string>();

    public ScannerOptions ToScannerOptions() => new()
    {
        MinimumSeverity = Severity,
        RedactPii = !IncludePii,
        IncludeHighEntropy = IncludeHighEntropy,
        IncludeGeneratedFiles = IncludeGenerated,
        FollowSymlinks = FollowSymlinks,
        MaxFileSizeBytes = MaxFileSizeBytes ?? 5 * 1024 * 1024,
        IncludeGlobs = Include,
        ExcludeGlobs = Exclude,
    };
}

public enum OutputFormat
{
    Console,
    Json,
    Sarif,
}
