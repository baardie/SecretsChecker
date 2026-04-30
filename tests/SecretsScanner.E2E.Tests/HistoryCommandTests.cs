using SecretsScanner.Cli.Commands;
using SecretsScanner.Cli.Configuration;
using SecretsScanner.Core.Findings;
using SecretsScanner.E2E.Tests.Fixtures;

namespace SecretsScanner.E2E.Tests;

public sealed class HistoryCommandTests : IDisposable
{
    private readonly TextWriter _origOut;
    private readonly TextWriter _origErr;
    private readonly StringWriter _capturedOut = new();
    private readonly StringWriter _capturedErr = new();

    public HistoryCommandTests()
    {
        _origOut = Console.Out;
        _origErr = Console.Error;
        Console.SetOut(_capturedOut);
        Console.SetError(_capturedErr);
    }

    public void Dispose()
    {
        Console.SetOut(_origOut);
        Console.SetError(_origErr);
    }

    [Fact]
    public async Task Nonexistent_path_returns_two()
    {
        var cli = new HistoryCliOptions { Path = Path.Combine(Path.GetTempPath(), "no-such-thing-" + Guid.NewGuid()) };

        var exit = await new HistoryCommand().ExecuteAsync(cli, CancellationToken.None);

        exit.Should().Be(2);
        _capturedErr.ToString().Should().Contain("path not found");
    }

    [Fact]
    public async Task Non_git_directory_returns_two()
    {
        var dir = Path.Combine(Path.GetTempPath(), "history-not-git-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(dir);
        try
        {
            var cli = new HistoryCliOptions { Path = dir };

            var exit = await new HistoryCommand().ExecuteAsync(cli, CancellationToken.None);

            exit.Should().Be(2);
            _capturedErr.ToString().Should().Contain("not a git repository");
        }
        finally
        {
            Directory.Delete(dir, recursive: true);
        }
    }

    [Fact]
    public async Task Conflicting_view_filters_return_two()
    {
        using var fixture = new FixtureRepo();
        fixture.Commit("seed", ("a.cs", "// hi"));

        var cli = new HistoryCliOptions { Path = fixture.Path, StillPresentOnly = true, RemovedOnly = true };

        var exit = await new HistoryCommand().ExecuteAsync(cli, CancellationToken.None);

        exit.Should().Be(2);
        _capturedErr.ToString().Should().Contain("mutually exclusive");
    }

    [Fact]
    public async Task Cap_policy_warns_and_returns_two_when_repository_exceeds_max_commits()
    {
        using var fixture = new FixtureRepo();
        fixture.Commit("c1", ("a.cs", "// 1"));
        fixture.Commit("c2", ("a.cs", "// 2"));
        fixture.Commit("c3", ("a.cs", "// 3"));

        var cli = new HistoryCliOptions { Path = fixture.Path, MaxCommits = 1 };

        var exit = await new HistoryCommand().ExecuteAsync(cli, CancellationToken.None);

        exit.Should().Be(2);
        _capturedErr.ToString().Should().Contain("--all-history");
    }

    [Fact]
    public async Task Cap_policy_is_lifted_by_all_history()
    {
        using var fixture = new FixtureRepo();
        fixture.Commit("c1", ("a.cs", "// 1"));
        fixture.Commit("c2", ("a.cs", "// 2"));
        fixture.Commit("c3", ("a.cs", "// 3"));

        var cli = new HistoryCliOptions { Path = fixture.Path, MaxCommits = 1, AllHistory = true };

        var exit = await new HistoryCommand().ExecuteAsync(cli, CancellationToken.None);

        exit.Should().Be(0, "no findings, but the cap is lifted so the scan completes");
    }

    [Fact]
    public async Task Findings_return_one()
    {
        using var fixture = new FixtureRepo();
        fixture.Commit("seed", ("a.cs", "// hi"));
        fixture.Commit("leak", ("a.cs", "var k = \"AKIAIOSFODNN7EXAMPLE\";"));

        var cli = new HistoryCliOptions { Path = fixture.Path, Severity = Severity.Medium };

        var exit = await new HistoryCommand().ExecuteAsync(cli, CancellationToken.None);

        exit.Should().Be(1);
    }

    [Fact]
    public async Task Json_output_writes_versioned_envelope_to_file()
    {
        using var fixture = new FixtureRepo();
        fixture.Commit("seed", ("a.cs", "// hi"));
        fixture.Commit("leak", ("a.cs", "var k = \"AKIAIOSFODNN7EXAMPLE\";"));

        var outPath = Path.Combine(fixture.Path, "history.json");
        var cli = new HistoryCliOptions
        {
            Path = fixture.Path,
            Severity = Severity.Medium,
            Format = OutputFormat.Json,
            Output = outPath,
        };

        var exit = await new HistoryCommand().ExecuteAsync(cli, CancellationToken.None);

        exit.Should().Be(1);
        var json = File.ReadAllText(outPath);
        json.Should().Contain("\"schemaVersion\": \"1\"");
        json.Should().Contain("\"AwsAccessKey\"");
        json.Should().Contain("\"history\"", "the source field for working-tree-secret history findings");
        json.Should().NotContain("AKIAIOSFODNN7EXAMPLE", "raw secret value must never appear in output");
    }

    [Fact]
    public async Task Still_present_only_drops_removed_findings()
    {
        using var fixture = new FixtureRepo();
        fixture.Commit("seed", ("a.cs", "// hi"));
        fixture.Commit("leak", ("a.cs", "var k = \"AKIAIOSFODNN7EXAMPLE\";"));
        fixture.Commit("clean", ("a.cs", "// removed"));

        var cli = new HistoryCliOptions { Path = fixture.Path, Severity = Severity.Medium, StillPresentOnly = true };

        var exit = await new HistoryCommand().ExecuteAsync(cli, CancellationToken.None);

        exit.Should().Be(0, "the only finding has stillPresent=false; --still-present-only filters it out");
    }

    [Fact]
    public async Task Removed_only_keeps_history_only_findings()
    {
        using var fixture = new FixtureRepo();
        fixture.Commit("seed", ("a.cs", "// hi"));
        fixture.Commit("leak", ("a.cs", "var k = \"AKIAIOSFODNN7EXAMPLE\";"));
        fixture.Commit("clean", ("a.cs", "// removed"));

        var cli = new HistoryCliOptions { Path = fixture.Path, Severity = Severity.Medium, RemovedOnly = true };

        var exit = await new HistoryCommand().ExecuteAsync(cli, CancellationToken.None);

        exit.Should().Be(1);
    }
}
