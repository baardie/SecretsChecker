using System.CommandLine;
using SecretsScanner.Cli;

namespace SecretsScanner.Cli.Tests;

/// <summary>
/// Root-command parse + invoke. The PRD exit-code table requires bad arguments to surface
/// as exit 2 (tool error), not the default 1 from System.CommandLine — the runner converts
/// parse errors before the handler runs.
/// </summary>
public sealed class ProgramTests : IDisposable
{
    private readonly TextWriter _origOut;
    private readonly TextWriter _origErr;
    private readonly StringWriter _capturedOut = new();
    private readonly StringWriter _capturedErr = new();
    private readonly string _dir;

    public ProgramTests()
    {
        _origOut = Console.Out;
        _origErr = Console.Error;
        Console.SetOut(_capturedOut);
        Console.SetError(_capturedErr);

        _dir = Path.Combine(Path.GetTempPath(), "secrets-scan-program-tests-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(_dir);
    }

    public void Dispose()
    {
        Console.SetOut(_origOut);
        Console.SetError(_origErr);
        try
        {
            if (Directory.Exists(_dir))
            {
                Directory.Delete(_dir, recursive: true);
            }
        }
        catch
        {
            // best effort
        }
    }

    [Fact]
    public async Task Help_returns_zero()
    {
        var exit = await Program.Main(new[] { "--help" });

        exit.Should().Be(0);
    }

    [Fact]
    public async Task Clean_path_returns_zero()
    {
        var exit = await Program.Main(new[] { "--path", _dir });

        exit.Should().Be(0);
    }

    [Fact]
    public async Task Findings_return_one()
    {
        File.WriteAllText(
            Path.Combine(_dir, "Program.cs"),
            "var key = \"AKIAIOSFODNN7EXAMPLE\";");

        var exit = await Program.Main(new[] { "--path", _dir });

        exit.Should().Be(1);
    }

    [Fact]
    public async Task Unknown_option_returns_two()
    {
        var exit = await Program.Main(new[] { "--definitely-not-a-real-flag" });

        exit.Should().Be(2);
    }

    [Fact]
    public async Task Invalid_severity_value_returns_two()
    {
        var exit = await Program.Main(new[] { "--severity", "bogus" });

        exit.Should().Be(2);
    }

    [Fact]
    public async Task Invalid_format_value_returns_two()
    {
        var exit = await Program.Main(new[] { "--format", "xml" });

        exit.Should().Be(2);
    }
}
