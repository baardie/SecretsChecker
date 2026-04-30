using SecretsScanner.Core.Findings;

namespace SecretsScanner.Core.Walking;

/// <summary>
/// R4 — answers <c>stillPresent</c> for a history match. Working-tree raw matches publish
/// their <c>(SecretType, ValueHash16)</c> pairs into a hash set; history-walker matches
/// look themselves up against it.
///
/// Properties guaranteed by the design:
///   • Path-independent — file renames don't break the link.
///   • Type-scoped — the same literal in two different secret-type contexts is two findings.
///   • No value leakage — the 16-byte SHA-256 truncation never crosses the library boundary;
///     only the resulting boolean reaches the public <see cref="HistoryFinding"/>.
/// </summary>
internal sealed class StillPresentChecker
{
    public static StillPresentChecker Empty { get; } = new(Array.Empty<RawMatch>());

    private readonly HashSet<string> _keys = new(StringComparer.Ordinal);

    public StillPresentChecker(IEnumerable<RawMatch> workingTreeMatches)
    {
        foreach (var m in workingTreeMatches)
        {
            _keys.Add(BuildKey(m.SecretType, m.ValueHash16));
        }
    }

    public bool IsStillPresent(RawMatch historyMatch)
        => _keys.Contains(BuildKey(historyMatch.SecretType, historyMatch.ValueHash16));

    public int Count => _keys.Count;

    private static string BuildKey(string secretType, byte[] hash16)
        => string.Concat(secretType, ":", Convert.ToHexString(hash16));
}
