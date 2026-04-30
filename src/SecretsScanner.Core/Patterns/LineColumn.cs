namespace SecretsScanner.Core.Patterns;

internal static class LineColumn
{
    /// <summary>
    /// Computes 1-based line and column for a character index in a text buffer. Treats LF as the
    /// line break; CRLF is handled because the LF still terminates the line.
    /// </summary>
    public static (int Line, int Column) For(string content, int index)
    {
        if (index < 0)
        {
            return (1, 1);
        }

        if (index > content.Length)
        {
            index = content.Length;
        }

        var line = 1;
        var lineStart = 0;
        for (var i = 0; i < index; i++)
        {
            if (content[i] == '\n')
            {
                line++;
                lineStart = i + 1;
            }
        }

        return (line, index - lineStart + 1);
    }
}
