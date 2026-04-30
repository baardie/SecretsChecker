namespace SecretsScanner.Cli.Output;

/// <summary>
/// Hand-rolled ANSI escape wrapper (R19). Decides whether colour is enabled based on the
/// <c>--color</c> flag, the <c>NO_COLOR</c> / <c>FORCE_COLOR</c> environment variables, and
/// whether stdout is redirected. .NET 7+ already enables Windows VT processing, so no native
/// interop is needed.
/// </summary>
public sealed class AnsiConsole
{
    private readonly TextWriter _out;
    private readonly bool _enabled;

    public AnsiConsole(TextWriter output, bool enabled)
    {
        _out = output;
        _enabled = enabled;
    }

    public bool ColourEnabled => _enabled;

    public static AnsiConsole CreateForStdout(ColorMode mode)
        => new(Console.Out, ResolveEnabled(mode, Console.IsOutputRedirected));

    public static bool ResolveEnabled(ColorMode mode, bool outputRedirected)
    {
        if (mode == ColorMode.Never)
        {
            return false;
        }

        if (mode == ColorMode.Always)
        {
            return true;
        }

        if (Environment.GetEnvironmentVariable("FORCE_COLOR") is { Length: > 0 })
        {
            return true;
        }

        if (Environment.GetEnvironmentVariable("NO_COLOR") is { Length: > 0 })
        {
            return false;
        }

        return !outputRedirected;
    }

    public void Write(string text) => _out.Write(text);

    public void WriteLine() => _out.WriteLine();

    public void WriteLine(string text) => _out.WriteLine(text);

    public void Write(string text, AnsiStyle style)
    {
        if (_enabled)
        {
            _out.Write(style.Open);
            _out.Write(text);
            _out.Write(AnsiStyle.Reset);
        }
        else
        {
            _out.Write(text);
        }
    }

    public void WriteLine(string text, AnsiStyle style)
    {
        Write(text, style);
        _out.WriteLine();
    }
}

public enum ColorMode
{
    Auto,
    Always,
    Never,
}

public readonly record struct AnsiStyle(string Open)
{
    public const string Reset = "\x1b[0m";

    public static readonly AnsiStyle Bold = new("\x1b[1m");
    public static readonly AnsiStyle Dim = new("\x1b[2m");
    public static readonly AnsiStyle Red = new("\x1b[31m");
    public static readonly AnsiStyle Green = new("\x1b[32m");
    public static readonly AnsiStyle Yellow = new("\x1b[33m");
    public static readonly AnsiStyle Blue = new("\x1b[34m");
    public static readonly AnsiStyle Magenta = new("\x1b[35m");
    public static readonly AnsiStyle Cyan = new("\x1b[36m");
    public static readonly AnsiStyle Grey = new("\x1b[90m");
    public static readonly AnsiStyle BoldRed = new("\x1b[1;31m");
    public static readonly AnsiStyle BoldYellow = new("\x1b[1;33m");
}
