namespace SecretsScanner.Core.Walking;

/// <summary>
/// Extracts added lines and their post-commit line numbers from a libgit2 patch text.
/// History scans only consider added hunks (the secret was introduced in this commit), so
/// deletions and context lines are dropped. Rename / mode-change headers without payload
/// hunks are also skipped.
/// </summary>
internal static class UnifiedDiffParser
{
    /// <summary>
    /// Yields every added line in <paramref name="patchText"/>, with its 1-based line number
    /// in the post-commit version of the file. Binary patches (no <c>@@</c> hunk header) and
    /// header-only entries yield nothing.
    /// </summary>
    public static IEnumerable<AddedLine> EnumerateAddedLines(string patchText)
    {
        if (string.IsNullOrEmpty(patchText))
        {
            yield break;
        }

        var newLine = -1;
        using var reader = new StringReader(patchText);
        string? line;
        while ((line = reader.ReadLine()) is not null)
        {
            if (line.StartsWith("@@", StringComparison.Ordinal))
            {
                newLine = ParseHunkNewStart(line);
                continue;
            }

            if (newLine < 0)
            {
                // Pre-hunk preamble (---, +++, diff --git, index, etc.). Skip.
                continue;
            }

            if (line.Length == 0)
            {
                // Blank line inside a hunk counts as a context line.
                newLine++;
                continue;
            }

            switch (line[0])
            {
                case '+':
                    if (line.StartsWith("+++", StringComparison.Ordinal))
                    {
                        // File header re-occurring inside a multi-file patch is rare but
                        // safe to ignore.
                        continue;
                    }

                    yield return new AddedLine(newLine, line.Length > 1 ? line[1..] : string.Empty);
                    newLine++;
                    break;

                case '-':
                    // Deletion — does not advance the new-side line counter.
                    break;

                case '\\':
                    // "\ No newline at end of file" — non-content marker.
                    break;

                default:
                    // Context line (' ' prefix) advances the new-side counter.
                    newLine++;
                    break;
            }
        }
    }

    /// <summary>
    /// Parses the new-side starting line from a hunk header of the form
    /// <c>@@ -old_start[,old_len] +new_start[,new_len] @@ ...</c>. Returns 1 if the new-start
    /// is missing (defensive — libgit2 always emits well-formed headers).
    /// </summary>
    private static int ParseHunkNewStart(string hunkHeader)
    {
        var plusIdx = hunkHeader.IndexOf('+');
        if (plusIdx < 0)
        {
            return 1;
        }

        var start = plusIdx + 1;
        var end = start;
        while (end < hunkHeader.Length && (char.IsDigit(hunkHeader[end])))
        {
            end++;
        }

        if (start == end)
        {
            return 1;
        }

        return int.Parse(hunkHeader.AsSpan(start, end - start));
    }
}

/// <summary>
/// One added line in a unified diff. <see cref="NewLineNumber"/> is the 1-based line number
/// in the post-commit version of the file.
/// </summary>
internal readonly record struct AddedLine(int NewLineNumber, string Text);
