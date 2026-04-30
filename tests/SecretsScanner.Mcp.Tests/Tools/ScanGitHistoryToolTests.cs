using System.Text.Json;
using LibGit2Sharp;
using SecretsScanner.Mcp.Security;
using SecretsScanner.Mcp.Tools;

namespace SecretsScanner.Mcp.Tests.Tools;

public sealed class ScanGitHistoryToolTests : IDisposable
{
    private readonly string _workspace;

    public ScanGitHistoryToolTests()
    {
        _workspace = Path.Combine(Path.GetTempPath(), "mcp-history-tool-tests-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(_workspace);
    }

    public void Dispose()
    {
        try
        {
            ForceDelete(_workspace);
        }
        catch
        {
            // best effort
        }
    }

    [Fact]
    public void Non_git_workspace_returns_a_structured_error()
    {
        var tool = NewTool();

        var response = tool.Execute(new ScanGitHistoryRequest { Path = _workspace });

        response.Error.Should().NotBeNullOrEmpty();
        response.Error.Should().Contain("not a git repository");
    }

    [Fact]
    public void Repo_with_a_leaked_secret_emits_a_history_finding_without_authorName_or_entropy()
    {
        InitRepo(out var sig);
        WriteAndCommit(sig, "Program.cs", "// hi", "seed");
        WriteAndCommit(sig, "Program.cs", "var k = \"AKIAIOSFODNN7EXAMPLE\";", "leak");

        var response = NewTool().Execute(new ScanGitHistoryRequest { Path = _workspace });

        response.Error.Should().BeNull();
        response.Findings.Should().ContainSingle();
        response.CommitsWalked.Should().Be(2);

        var json = JsonSerializer.Serialize(response.Findings[0], new JsonSerializerOptions { PropertyNamingPolicy = JsonNamingPolicy.CamelCase });
        json.Should().NotContain("authorName");
        json.Should().NotContain("entropy");
        json.Should().NotContain("Test Author");
        json.Should().NotContain("test@example.com");
        json.Should().NotContain("AKIAIOSFODNN7EXAMPLE");
        json.Should().Contain("\"source\":\"history\"");
        json.Should().Contain("\"stillPresent\":true");
    }

    [Fact]
    public void Path_outside_workspace_is_rejected()
    {
        var tool = NewTool();
        var outside = Path.GetTempPath();

        var response = tool.Execute(new ScanGitHistoryRequest { Path = outside });

        response.Error.Should().Contain("outside workspace");
    }

    [Fact]
    public void Invalid_since_returns_a_structured_error()
    {
        InitRepo(out _);

        var response = NewTool().Execute(new ScanGitHistoryRequest { Path = _workspace, Since = "yesterday" });

        response.Error.Should().Contain("invalid since");
    }

    [Fact]
    public void MaxCommits_must_be_positive()
    {
        InitRepo(out _);

        var response = NewTool().Execute(new ScanGitHistoryRequest { Path = _workspace, MaxCommits = 0 });

        response.Error.Should().Contain("must be positive");
    }

    [Fact]
    public void Invalid_severity_returns_a_structured_error()
    {
        InitRepo(out _);

        var response = NewTool().Execute(new ScanGitHistoryRequest { Path = _workspace, Severity = "extreme" });

        response.Error.Should().Contain("invalid severity");
    }

    private ScanGitHistoryTool NewTool()
        => new(new WorkspaceBoundary(_workspace), ResourceCaps.Default);

    private void InitRepo(out Signature signature)
    {
        Repository.Init(_workspace);
        signature = new Signature("Test Author", "test@example.com", new DateTimeOffset(2024, 3, 15, 10, 0, 0, TimeSpan.Zero));
    }

    private void WriteAndCommit(Signature sig, string relPath, string content, string message)
    {
        var full = Path.Combine(_workspace, relPath);
        Directory.CreateDirectory(Path.GetDirectoryName(full) ?? _workspace);
        File.WriteAllText(full, content);

        using var repo = new Repository(_workspace);
        Commands.Stage(repo, relPath);
        repo.Commit(message, sig, sig, new CommitOptions { AllowEmptyCommit = true });
    }

    private static void ForceDelete(string path)
    {
        if (!Directory.Exists(path))
        {
            return;
        }
        foreach (var file in Directory.EnumerateFiles(path, "*", SearchOption.AllDirectories))
        {
            try { File.SetAttributes(file, FileAttributes.Normal); } catch { /* ignore */ }
        }
        Directory.Delete(path, recursive: true);
    }
}
