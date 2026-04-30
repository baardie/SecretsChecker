using System.Collections.Frozen;

namespace SecretsScanner.Core.Patterns;

/// <summary>
/// Values that should never be reported as findings — typical placeholder strings developers
/// use as obvious "fill me in" markers. Per PRD §Detection patterns.
/// </summary>
public static class PlaceholderFilter
{
    private static readonly FrozenSet<string> Placeholders =
        new[]
        {
            "",
            "changeme",
            "change-me",
            "your-secret-here",
            "your-key-here",
            "your-password-here",
            "todo",
            "tbd",
            "placeholder",
            "<secret>",
            "<password>",
            "<key>",
            "***",
            "xxxx",
            "xxxxx",
            "xxxxxx",
            "enter-your-key",
            "example",
            "sample",
            "dummy",
            "fake",
            "test",
            "null",
            "none",
        }
        .ToFrozenSet(StringComparer.OrdinalIgnoreCase);

    public static bool IsPlaceholder(string value)
    {
        if (string.IsNullOrWhiteSpace(value))
        {
            return true;
        }

        var trimmed = value.Trim().Trim('"', '\'');
        if (Placeholders.Contains(trimmed))
        {
            return true;
        }

        // Strings consisting only of '*' or 'x' or '_' are placeholders.
        var allMask = true;
        foreach (var c in trimmed)
        {
            if (c != '*' && c != 'x' && c != 'X' && c != '_' && c != '.' && c != '?')
            {
                allMask = false;
                break;
            }
        }

        return allMask;
    }
}
