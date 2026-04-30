namespace SecretsScanner.Core.Findings;

/// <summary>
/// Sole converter from internal <see cref="RawMatch"/> to public <see cref="Finding"/>.
/// Computes the masked hint, rounds entropy to 1 decimal place (R1), and verifies fail-closed
/// that the produced hint contains no character from the captured value.
/// </summary>
internal static class Sanitiser
{
    private const string Mask = "***";

    public static Finding ToWorkingTreeFinding(RawMatch raw)
    {
        var hint = BuildHint(raw);
        return new Finding
        {
            Source = FindingSource.WorkingTree,
            File = raw.File,
            Line = raw.Line,
            Column = raw.Column,
            SecretType = raw.SecretType,
            Severity = raw.Severity,
            Hint = hint,
            Entropy = Math.Round(ShannonEntropy(raw.Value), 1, MidpointRounding.AwayFromZero),
            SuggestedFix = raw.SuggestedFix,
        };
    }

    public static HistoryFinding ToHistoryFinding(
        RawMatch raw,
        string commitSha,
        DateTimeOffset commitDate,
        string authorName,
        IReadOnlyList<string> branches,
        bool stillPresent)
    {
        var hint = BuildHint(raw);
        return new HistoryFinding
        {
            Source = FindingSource.History,
            File = raw.File,
            Line = raw.Line,
            Column = raw.Column,
            SecretType = raw.SecretType,
            Severity = raw.Severity,
            Hint = hint,
            Entropy = Math.Round(ShannonEntropy(raw.Value), 1, MidpointRounding.AwayFromZero),
            SuggestedFix = raw.SuggestedFix,
            CommitSha = commitSha,
            CommitShort = commitSha.Length >= 7 ? commitSha[..7] : commitSha,
            CommitDate = commitDate,
            AuthorName = authorName,
            Branches = branches,
            StillPresent = stillPresent,
        };
    }

    public static CommitMessageFinding ToCommitMessageFinding(
        RawMatch raw,
        string commitSha,
        DateTimeOffset commitDate,
        string authorName)
    {
        var hint = BuildHint(raw);
        return new CommitMessageFinding
        {
            Source = FindingSource.CommitMessage,
            File = "<commit-message>",
            Line = raw.Line,
            Column = raw.Column,
            SecretType = raw.SecretType,
            Severity = raw.Severity,
            Hint = hint,
            Entropy = Math.Round(ShannonEntropy(raw.Value), 1, MidpointRounding.AwayFromZero),
            SuggestedFix = raw.SuggestedFix,
            CommitSha = commitSha,
            CommitShort = commitSha.Length >= 7 ? commitSha[..7] : commitSha,
            CommitDate = commitDate,
            AuthorName = authorName,
        };
    }

    /// <summary>
    /// Builds the masked hint. If the pattern captured a key (e.g. "Password") the hint is
    /// "Password=***"; otherwise it falls back to "&lt;secretType&gt;=***".
    ///
    /// Fail-closed guards (R1):
    ///   1. The key token must consist only of identifier-safe characters (letters, digits,
    ///      and a small set of separators). Anything else suggests value contamination and
    ///      drops to the static <c>SecretType</c> label.
    ///   2. The produced hint must not contain any contiguous substring of length 4+ from
    ///      the captured value. This catches accidental value-bleed without forbidding the
    ///      single-character overlap that legitimate field names (like "Password" containing
    ///      'a' or 's') will always have with high-entropy values.
    /// </summary>
    private static string BuildHint(RawMatch raw)
    {
        var keyToken = string.IsNullOrEmpty(raw.KeyName) ? raw.SecretType : raw.KeyName!;

        if (!IsKeyTokenSafe(keyToken))
        {
            keyToken = raw.SecretType;
        }

        var hint = $"{keyToken}={Mask}";

        if (ContainsValueSubstring(hint, raw.Value, minLength: 4))
        {
            hint = $"{raw.SecretType}={Mask}";
        }

        return hint;
    }

    private static bool IsKeyTokenSafe(string token)
    {
        if (string.IsNullOrEmpty(token))
        {
            return false;
        }

        for (var i = 0; i < token.Length; i++)
        {
            var c = token[i];
            var ok = char.IsLetterOrDigit(c) || c is '_' or '-' or '.' or ':';
            if (!ok)
            {
                return false;
            }
        }

        return true;
    }

    private static bool ContainsValueSubstring(string candidate, string value, int minLength)
    {
        if (string.IsNullOrEmpty(value) || value.Length < minLength)
        {
            return false;
        }

        // Hoist the candidate span outside the loop so we don't re-create it per window.
        var candidateSpan = candidate.AsSpan();
        for (var i = 0; i + minLength <= value.Length; i++)
        {
            var window = value.AsSpan(i, minLength);
            if (candidateSpan.IndexOf(window, StringComparison.Ordinal) >= 0)
            {
                return true;
            }
        }

        return false;
    }

    /// <summary>
    /// Shannon entropy in bits per character. Used as a heuristic signal only; never reveals
    /// the underlying value.
    /// </summary>
    public static double ShannonEntropy(string value)
    {
        if (string.IsNullOrEmpty(value))
        {
            return 0d;
        }

        Span<int> counts = stackalloc int[256];
        var totalBytes = 0;
        foreach (var c in value)
        {
            if (c < 256)
            {
                counts[c]++;
                totalBytes++;
            }
        }

        if (totalBytes == 0)
        {
            return 0d;
        }

        var entropy = 0d;
        for (var i = 0; i < counts.Length; i++)
        {
            if (counts[i] == 0)
            {
                continue;
            }

            var p = (double)counts[i] / totalBytes;
            entropy -= p * Math.Log2(p);
        }

        return entropy;
    }
}
