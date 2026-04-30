using System.Text.RegularExpressions;

namespace SecretsScanner.Core.Findings;

/// <summary>
/// Applies PII redaction to findings before they reach an output channel (R8). Default-on for
/// every output path. The MCP mapper forces this on regardless of config.
/// </summary>
public static partial class Redaction
{
    public const string RedactedAuthor = "[redacted]";

    public static Finding Apply(Finding finding, bool redactPii)
    {
        if (!redactPii)
        {
            return finding;
        }

        return finding switch
        {
            HistoryFinding h => h with
            {
                File = RedactHomePath(h.File),
                AuthorName = RedactedAuthor,
            },
            CommitMessageFinding c => c with
            {
                AuthorName = RedactedAuthor,
            },
            _ => finding with { File = RedactHomePath(finding.File) },
        };
    }

    /// <summary>
    /// Replaces a leading <c>/Users/&lt;name&gt;</c>, <c>C:\Users\&lt;name&gt;</c>, or
    /// <c>/home/&lt;name&gt;</c> prefix with <c>~</c>. Drops the username in the process.
    /// </summary>
    public static string RedactHomePath(string path)
    {
        if (string.IsNullOrEmpty(path))
        {
            return path;
        }

        var match = HomePathRegex().Match(path);
        if (!match.Success)
        {
            return path;
        }

        var rest = path[match.Length..];
        rest = rest.TrimStart('/', '\\');
        return rest.Length == 0 ? "~" : "~/" + rest.Replace('\\', '/');
    }

    [GeneratedRegex(@"^(?:/Users/[^/]+|/home/[^/]+|[A-Za-z]:\\Users\\[^\\]+)",
        RegexOptions.IgnoreCase | RegexOptions.CultureInvariant)]
    private static partial Regex HomePathRegex();
}
