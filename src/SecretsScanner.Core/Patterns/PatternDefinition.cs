using System.Text.RegularExpressions;
using SecretsScanner.Core.Findings;

namespace SecretsScanner.Core.Patterns;

/// <summary>
/// Structured pattern definition (R3). Patterns declare keywords for a cheap pre-filter so the
/// regex only runs on files that actually contain a relevant token. Regex is compiled with a
/// hard timeout to bound ReDoS risk.
/// </summary>
public sealed record PatternDefinition
{
    public required string Id { get; init; }
    public required string Description { get; init; }
    public required string SecretType { get; init; }
    public required Severity DefaultSeverity { get; init; }
    public required string SuggestedFix { get; init; }
    public required Regex Regex { get; init; }
    public required IReadOnlyList<string> Keywords { get; init; }
    public required string ValueGroupName { get; init; }
    public string? KeyGroupName { get; init; }
    public IReadOnlyList<string> FileExtensions { get; init; } = Array.Empty<string>();
    public double? MinEntropy { get; init; }
    public bool RequirePlaceholderFilter { get; init; } = true;

    public bool AppliesTo(string filePath)
    {
        if (FileExtensions.Count == 0)
        {
            return true;
        }

        var ext = Path.GetExtension(filePath);
        for (var i = 0; i < FileExtensions.Count; i++)
        {
            if (string.Equals(FileExtensions[i], ext, StringComparison.OrdinalIgnoreCase))
            {
                return true;
            }
        }

        return false;
    }
}
