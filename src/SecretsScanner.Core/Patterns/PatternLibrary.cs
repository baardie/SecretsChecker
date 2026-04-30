using SecretsScanner.Core.Findings;

namespace SecretsScanner.Core.Patterns;

/// <summary>
/// Registry and dispatcher for all <see cref="PatternDefinition"/>s. Applies the keyword
/// pre-filter (skip the regex entirely if no keyword appears in the file) and runs each
/// matching pattern under the regex's compiled timeout.
/// </summary>
public sealed class PatternLibrary
{
    private readonly IReadOnlyList<PatternDefinition> _patterns;
    private readonly string[] _uniqueKeywords;

    public PatternLibrary(IEnumerable<PatternDefinition> patterns)
    {
        _patterns = patterns.ToArray();
        // Many patterns share keywords ("Password=" appears in multiple connection-string
        // detectors, "ghs_" in two GitHub detectors, etc.). Dedup once at library
        // construction so per-file scanning visits each keyword at most once instead of
        // once per pattern.
        _uniqueKeywords = _patterns
            .SelectMany(p => p.Keywords)
            .Distinct(StringComparer.OrdinalIgnoreCase)
            .ToArray();
    }

    public static PatternLibrary CreateDefault(bool includeHighEntropy = false)
    {
        if (!includeHighEntropy)
        {
            return new PatternLibrary(BuiltInPatterns.All);
        }

        var patterns = new List<PatternDefinition>(BuiltInPatterns.All) { BuiltInPatterns.HighEntropy };
        return new PatternLibrary(patterns);
    }

    public IReadOnlyList<PatternDefinition> All => _patterns;

    /// <summary>
    /// Scans a file's textual content for raw matches. The caller has already determined the
    /// file is text and decoded it into a UTF-16 string; this method is purely about pattern
    /// dispatch. <see cref="RawMatch"/> instances stay inside the core library.
    /// </summary>
    internal IEnumerable<RawMatch> Scan(string relativePath, string content)
    {
        if (string.IsNullOrEmpty(content))
        {
            yield break;
        }

        var presentKeywords = ComputePresentKeywords(content);

        for (var p = 0; p < _patterns.Count; p++)
        {
            var pattern = _patterns[p];

            if (!pattern.AppliesTo(relativePath))
            {
                continue;
            }

            if (!HasAnyPresentKeyword(pattern.Keywords, presentKeywords))
            {
                continue;
            }

            foreach (var raw in EvaluatePattern(pattern, relativePath, content))
            {
                yield return raw;
            }
        }
    }

    /// <summary>
    /// Variant for content with no on-disk path, e.g. commit messages (R16). Every pattern is
    /// considered regardless of file-extension scoping; the keyword pre-filter still applies.
    /// </summary>
    internal IEnumerable<RawMatch> ScanAllPatterns(string virtualPath, string content)
    {
        if (string.IsNullOrEmpty(content))
        {
            yield break;
        }

        var presentKeywords = ComputePresentKeywords(content);

        for (var p = 0; p < _patterns.Count; p++)
        {
            var pattern = _patterns[p];

            if (!HasAnyPresentKeyword(pattern.Keywords, presentKeywords))
            {
                continue;
            }

            foreach (var raw in EvaluatePattern(pattern, virtualPath, content))
            {
                yield return raw;
            }
        }
    }

    /// <summary>
    /// Single pass over the file content: returns a hash set of unique keywords (case-
    /// insensitive) that appear at least once. Each pattern then asks the set rather than
    /// re-scanning the content.
    /// </summary>
    private HashSet<string> ComputePresentKeywords(string content)
    {
        var set = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        for (var i = 0; i < _uniqueKeywords.Length; i++)
        {
            var keyword = _uniqueKeywords[i];
            if (content.Contains(keyword, StringComparison.OrdinalIgnoreCase))
            {
                set.Add(keyword);
            }
        }
        return set;
    }

    private static bool HasAnyPresentKeyword(IReadOnlyList<string> patternKeywords, HashSet<string> presentKeywords)
    {
        if (patternKeywords.Count == 0)
        {
            return true;
        }

        for (var i = 0; i < patternKeywords.Count; i++)
        {
            if (presentKeywords.Contains(patternKeywords[i]))
            {
                return true;
            }
        }
        return false;
    }

    private static IEnumerable<RawMatch> EvaluatePattern(PatternDefinition pattern, string relativePath, string content)
    {
        System.Text.RegularExpressions.MatchCollection matches;
        try
        {
            matches = pattern.Regex.Matches(content);
        }
        catch (System.Text.RegularExpressions.RegexMatchTimeoutException)
        {
            yield break;
        }

        foreach (System.Text.RegularExpressions.Match match in matches)
        {
            if (!match.Success)
            {
                continue;
            }

            var valueGroup = match.Groups[pattern.ValueGroupName];
            if (!valueGroup.Success)
            {
                continue;
            }

            var value = valueGroup.Value;
            if (string.IsNullOrEmpty(value))
            {
                continue;
            }

            if (pattern.RequirePlaceholderFilter && PlaceholderFilter.IsPlaceholder(value))
            {
                continue;
            }

            if (pattern.MinEntropy is { } minEntropy && Sanitiser.ShannonEntropy(value) < minEntropy)
            {
                continue;
            }

            string? keyName = null;
            if (pattern.KeyGroupName is { } keyGroupName)
            {
                var keyGroup = match.Groups[keyGroupName];
                if (keyGroup.Success && !string.IsNullOrEmpty(keyGroup.Value))
                {
                    keyName = keyGroup.Value;
                }
            }

            var (line, column) = LineColumn.For(content, valueGroup.Index);

            yield return new RawMatch
            {
                PatternId = pattern.Id,
                SecretType = pattern.SecretType,
                Severity = pattern.DefaultSeverity,
                SuggestedFix = pattern.SuggestedFix,
                File = relativePath,
                Line = line,
                Column = column,
                Value = value,
                KeyName = keyName,
            };
        }
    }

}
