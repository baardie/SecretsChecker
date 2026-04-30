using SecretsScanner.Cli.Output;

namespace SecretsScanner.Cli.Tests.Output;

/// <summary>
/// R19 — colour decision logic. Order: explicit <c>--color always|never</c> wins;
/// otherwise <c>FORCE_COLOR</c> beats <c>NO_COLOR</c> beats stdout-redirection. JSON / SARIF
/// reporters bypass <see cref="AnsiConsole"/> entirely (verified in the reporter tests).
/// </summary>
[Collection("EnvSerialized")]
public sealed class AnsiConsoleTests : IDisposable
{
    private readonly string? _origNoColor;
    private readonly string? _origForceColor;

    public AnsiConsoleTests()
    {
        _origNoColor = Environment.GetEnvironmentVariable("NO_COLOR");
        _origForceColor = Environment.GetEnvironmentVariable("FORCE_COLOR");
        Environment.SetEnvironmentVariable("NO_COLOR", null);
        Environment.SetEnvironmentVariable("FORCE_COLOR", null);
    }

    public void Dispose()
    {
        Environment.SetEnvironmentVariable("NO_COLOR", _origNoColor);
        Environment.SetEnvironmentVariable("FORCE_COLOR", _origForceColor);
    }

    [Fact]
    public void Mode_Never_disables_colour_even_when_FORCE_COLOR_is_set()
    {
        Environment.SetEnvironmentVariable("FORCE_COLOR", "1");

        AnsiConsole.ResolveEnabled(ColorMode.Never, outputRedirected: false).Should().BeFalse();
    }

    [Fact]
    public void Mode_Always_enables_colour_even_when_NO_COLOR_is_set_and_redirected()
    {
        Environment.SetEnvironmentVariable("NO_COLOR", "1");

        AnsiConsole.ResolveEnabled(ColorMode.Always, outputRedirected: true).Should().BeTrue();
    }

    [Fact]
    public void Mode_Auto_with_FORCE_COLOR_enables_colour_even_when_redirected()
    {
        Environment.SetEnvironmentVariable("FORCE_COLOR", "1");

        AnsiConsole.ResolveEnabled(ColorMode.Auto, outputRedirected: true).Should().BeTrue();
    }

    [Fact]
    public void Mode_Auto_with_FORCE_COLOR_beats_NO_COLOR()
    {
        Environment.SetEnvironmentVariable("FORCE_COLOR", "1");
        Environment.SetEnvironmentVariable("NO_COLOR", "1");

        AnsiConsole.ResolveEnabled(ColorMode.Auto, outputRedirected: false).Should().BeTrue();
    }

    [Fact]
    public void Mode_Auto_with_NO_COLOR_disables_colour_even_when_attached_to_a_tty()
    {
        Environment.SetEnvironmentVariable("NO_COLOR", "1");

        AnsiConsole.ResolveEnabled(ColorMode.Auto, outputRedirected: false).Should().BeFalse();
    }

    [Fact]
    public void Mode_Auto_with_no_env_falls_back_to_tty_detection()
    {
        AnsiConsole.ResolveEnabled(ColorMode.Auto, outputRedirected: false).Should().BeTrue();
        AnsiConsole.ResolveEnabled(ColorMode.Auto, outputRedirected: true).Should().BeFalse();
    }

    [Fact]
    public void Empty_FORCE_COLOR_value_is_treated_as_unset()
    {
        Environment.SetEnvironmentVariable("FORCE_COLOR", string.Empty);

        AnsiConsole.ResolveEnabled(ColorMode.Auto, outputRedirected: true).Should().BeFalse();
    }

    [Fact]
    public void Write_with_style_emits_escape_when_enabled()
    {
        var writer = new StringWriter();
        var console = new AnsiConsole(writer, enabled: true);

        console.Write("hello", AnsiStyle.Red);

        writer.ToString().Should().Be("\x1b[31mhello\x1b[0m");
    }

    [Fact]
    public void Write_with_style_omits_escape_when_disabled()
    {
        var writer = new StringWriter();
        var console = new AnsiConsole(writer, enabled: false);

        console.Write("hello", AnsiStyle.Red);

        writer.ToString().Should().Be("hello");
    }
}
