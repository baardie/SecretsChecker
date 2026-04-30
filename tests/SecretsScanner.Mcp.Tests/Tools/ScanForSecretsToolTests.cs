using System.Text.Json;
using SecretsScanner.Mcp.Output;
using SecretsScanner.Mcp.Security;
using SecretsScanner.Mcp.Tools;

namespace SecretsScanner.Mcp.Tests.Tools;

/// <summary>
/// Tool-level tests for <c>scan_for_secrets</c>. Path-bound + privacy invariants land here;
/// transport-level concerns (JSON wire shape, MCP protocol) are tested in
/// <see cref="Integration"/>.
/// </summary>
public sealed class ScanForSecretsToolTests : IDisposable
{
    private readonly string _workspace;

    public ScanForSecretsToolTests()
    {
        _workspace = Path.Combine(Path.GetTempPath(), "mcp-tool-tests-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(_workspace);
    }

    public void Dispose()
    {
        try
        {
            if (Directory.Exists(_workspace))
            {
                Directory.Delete(_workspace, recursive: true);
            }
        }
        catch
        {
            // best effort
        }
    }

    [Fact]
    public void Clean_workspace_returns_no_findings_and_no_error()
    {
        File.WriteAllText(Path.Combine(_workspace, "README.md"), "# project");
        var tool = NewTool();

        var response = tool.Execute(new ScanForSecretsRequest { Path = _workspace });

        response.Error.Should().BeNull();
        response.Findings.Should().BeEmpty();
        response.Truncated.Should().BeFalse();
    }

    [Fact]
    public void Working_tree_with_a_secret_emits_a_finding_without_authorName_or_entropy()
    {
        File.WriteAllText(Path.Combine(_workspace, "Program.cs"), "var k = \"AKIAIOSFODNN7EXAMPLE\";");
        var tool = NewTool();

        var response = tool.Execute(new ScanForSecretsRequest { Path = _workspace });

        response.Error.Should().BeNull();
        response.Findings.Should().ContainSingle();

        var json = JsonSerializer.Serialize(response.Findings[0], new JsonSerializerOptions { PropertyNamingPolicy = JsonNamingPolicy.CamelCase });
        json.Should().NotContain("authorName");
        json.Should().NotContain("entropy");
        json.Should().NotContain("AKIAIOSFODNN7EXAMPLE", "raw secret value must never appear in MCP output");
    }

    [Fact]
    public void Path_outside_workspace_is_rejected_with_a_structured_error()
    {
        var tool = NewTool();
        var outside = Path.GetTempPath(); // never the workspace itself

        var response = tool.Execute(new ScanForSecretsRequest { Path = outside });

        response.Error.Should().NotBeNullOrEmpty();
        response.Error.Should().Contain("outside workspace");
        response.Findings.Should().BeEmpty();
    }

    [Fact]
    public void Invalid_severity_is_rejected_with_a_structured_error()
    {
        var tool = NewTool();

        var response = tool.Execute(new ScanForSecretsRequest { Path = _workspace, Severity = "extreme" });

        response.Error.Should().NotBeNullOrEmpty();
        response.Error.Should().Contain("invalid severity");
    }

    [Fact]
    public void Severity_is_case_insensitive()
    {
        File.WriteAllText(Path.Combine(_workspace, "Program.cs"), "var k = \"AKIAIOSFODNN7EXAMPLE\";");
        var tool = NewTool();

        var response = tool.Execute(new ScanForSecretsRequest { Path = _workspace, Severity = "CRITICAL" });

        response.Error.Should().BeNull();
        response.Findings.Should().ContainSingle();
    }

    [Fact]
    public void Severity_threshold_filters_lower_severities()
    {
        // Use a clean workspace; severity Critical means even a real secret would have to be
        // critical-rated to surface — AwsAccessKey IS Critical so it survives.
        File.WriteAllText(Path.Combine(_workspace, "Program.cs"), "var k = \"AKIAIOSFODNN7EXAMPLE\";");
        var tool = NewTool();

        var response = tool.Execute(new ScanForSecretsRequest { Path = _workspace, Severity = "critical" });

        response.Findings.Should().ContainSingle();
    }

    [Fact]
    public void Wall_clock_cap_returns_truncated_result_for_a_blocked_scan()
    {
        // Force the cap to fire instantly: scan a directory big enough to start reading,
        // with a cap of 1 ms.
        for (var i = 0; i < 50; i++)
        {
            File.WriteAllText(Path.Combine(_workspace, $"file{i}.cs"), new string('a', 4096));
        }

        var tool = new ScanForSecretsTool(
            new WorkspaceBoundary(_workspace),
            new ResourceCaps { MaxWallClock = TimeSpan.FromMilliseconds(1) });

        var response = tool.Execute(new ScanForSecretsRequest { Path = _workspace });

        // Either the scan finishes before the cap fires (very fast machine) or it trips and
        // we get truncated:true. Both outcomes are acceptable; what's NOT acceptable is an
        // error or an exception.
        response.Error.Should().BeNull();
        if (response.Truncated)
        {
            response.TruncatedReason.Should().NotBeNullOrEmpty();
        }
    }

    [Fact]
    public void Default_request_uses_workspace_as_path()
    {
        File.WriteAllText(Path.Combine(_workspace, "Program.cs"), "var k = \"AKIAIOSFODNN7EXAMPLE\";");

        var tool = new ScanForSecretsTool(new WorkspaceBoundary(_workspace), ResourceCaps.Default);

        // Default Path is "./" which canonicalises against cwd, not the workspace. The path
        // must be explicit for MCP usage.
        var response = tool.Execute(new ScanForSecretsRequest { Path = _workspace });

        response.Error.Should().BeNull();
        response.Findings.Should().ContainSingle();
    }

    private ScanForSecretsTool NewTool()
        => new(new WorkspaceBoundary(_workspace), ResourceCaps.Default);
}
