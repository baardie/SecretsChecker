using SecretsScanner.Cli.Commands;
using SecretsScanner.Cli.Configuration;
using SecretsScanner.Core.Findings;

namespace SecretsScanner.Cli.Tests.Commands;

/// <summary>
/// Exit codes per PRD §CLI usage:
///   0 — no findings at or above the minimum severity
///   1 — one or more findings found
///   2 — tool error (bad arguments, unreadable path, etc.)
/// </summary>
public sealed class ScanCommandTests : IDisposable
{
    private readonly string _dir;
    private readonly TextWriter _origOut;
    private readonly StringWriter _capturedOut;

    public ScanCommandTests()
    {
        _dir = Path.Combine(Path.GetTempPath(), "secrets-scan-cmd-tests-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(_dir);

        _origOut = Console.Out;
        _capturedOut = new StringWriter();
        Console.SetOut(_capturedOut);
    }

    public void Dispose()
    {
        Console.SetOut(_origOut);
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
    public async Task Clean_directory_returns_zero()
    {
        File.WriteAllText(Path.Combine(_dir, "Program.cs"), "Console.WriteLine(\"hi\");");
        var options = new CliOptions { Path = _dir };

        var exit = await new ScanCommand().ExecuteAsync(options, CancellationToken.None);

        exit.Should().Be(0);
    }

    [Fact]
    public async Task Findings_return_one()
    {
        File.WriteAllText(
            Path.Combine(_dir, "Program.cs"),
            "var key = \"AKIAIOSFODNN7EXAMPLE\";");
        var options = new CliOptions { Path = _dir, Severity = Severity.Medium };

        var exit = await new ScanCommand().ExecuteAsync(options, CancellationToken.None);

        exit.Should().Be(1);
    }

    [Fact]
    public async Task Nonexistent_path_returns_two()
    {
        var options = new CliOptions { Path = Path.Combine(_dir, "definitely-not-here") };

        var exit = await new ScanCommand().ExecuteAsync(options, CancellationToken.None);

        exit.Should().Be(2);
    }

    [Fact]
    public async Task Baseline_round_trip_suppresses_findings_to_zero()
    {
        File.WriteAllText(
            Path.Combine(_dir, "Program.cs"),
            "var key = \"AKIAIOSFODNN7EXAMPLE\";");

        var baselinePath = Path.Combine(_dir, "baseline.json");

        var firstRun = new CliOptions { Path = _dir, WriteBaseline = baselinePath, Severity = Severity.Medium };
        var firstExit = await new ScanCommand().ExecuteAsync(firstRun, CancellationToken.None);
        firstExit.Should().Be(1, "first run records the finding and exits non-zero");

        var secondRun = new CliOptions { Path = _dir, Baseline = baselinePath, Severity = Severity.Medium };
        var secondExit = await new ScanCommand().ExecuteAsync(secondRun, CancellationToken.None);

        secondExit.Should().Be(0, "second run suppresses the baselined finding and exits clean");
    }

    [Fact]
    public async Task Json_output_writes_to_specified_file()
    {
        File.WriteAllText(
            Path.Combine(_dir, "Program.cs"),
            "var key = \"AKIAIOSFODNN7EXAMPLE\";");
        var outputPath = Path.Combine(_dir, "out.json");
        var options = new CliOptions
        {
            Path = _dir,
            Severity = Severity.Medium,
            Format = OutputFormat.Json,
            Output = outputPath,
        };

        var exit = await new ScanCommand().ExecuteAsync(options, CancellationToken.None);

        exit.Should().Be(1);
        File.Exists(outputPath).Should().BeTrue();
        var json = File.ReadAllText(outputPath);
        json.Should().Contain("\"schemaVersion\": \"1\"");
        json.Should().Contain("\"AwsAccessKey\"");
        json.Should().NotContain("AKIAIOSFODNN7EXAMPLE", "raw secret value must never appear in output");
    }
}
