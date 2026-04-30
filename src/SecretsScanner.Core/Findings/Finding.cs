namespace SecretsScanner.Core.Findings;

/// <summary>
/// Public, sanitised finding. Carries no raw secret value — only location, masked hint, and
/// derived metadata. The single source of these is <see cref="Sanitiser"/> inside the core
/// library.
/// </summary>
public record Finding
{
    public required FindingSource Source { get; init; }
    public required string File { get; init; }
    public required int Line { get; init; }
    public required int Column { get; init; }
    public required string SecretType { get; init; }
    public required Severity Severity { get; init; }
    public required string Hint { get; init; }
    public required double Entropy { get; init; }
    public required string SuggestedFix { get; init; }
}
