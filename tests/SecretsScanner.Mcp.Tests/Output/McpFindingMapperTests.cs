using System.Text.Json;
using SecretsScanner.Core.Findings;
using SecretsScanner.Mcp.Output;

namespace SecretsScanner.Mcp.Tests.Output;

/// <summary>
/// R1 + R8 — privacy invariants enforced by the MCP boundary, in addition to whatever the
/// core sanitiser already did. Test discipline: serialise each mapped DTO with the exact
/// settings the transport will use, and assert against the produced JSON byte stream.
/// </summary>
public sealed class McpFindingMapperTests
{
    private static readonly JsonSerializerOptions Options = new()
    {
        WriteIndented = false,
        PropertyNamingPolicy = JsonNamingPolicy.CamelCase,
    };

    [Fact]
    public void Working_tree_finding_omits_entropy()
    {
        var finding = NewWorkingTree();

        var json = Serialise(McpFindingMapper.Map(finding));

        json.Should().NotContain("entropy");
        json.Should().Contain("\"hint\":\"Password=***\"");
    }

    [Fact]
    public void History_finding_omits_entropy_and_authorName()
    {
        var finding = NewHistory();

        var json = Serialise(McpFindingMapper.Map(finding));

        json.Should().NotContain("entropy");
        json.Should().NotContain("authorName", "R8 forbids author identity in MCP responses");
        json.Should().NotContain("Jane Smith");
        json.Should().Contain("\"commitSha\"");
        json.Should().Contain("\"stillPresent\":false");
    }

    [Fact]
    public void Commit_message_finding_omits_entropy_and_authorName()
    {
        var finding = NewCommitMessage();

        var json = Serialise(McpFindingMapper.Map(finding));

        json.Should().NotContain("entropy");
        json.Should().NotContain("authorName");
        json.Should().NotContain("Alex");
        json.Should().Contain("\"source\":\"commitMessage\"");
    }

    [Fact]
    public void History_finding_emits_all_required_history_fields()
    {
        var finding = NewHistory();

        var json = Serialise(McpFindingMapper.Map(finding));

        json.Should().Contain("\"source\":\"history\"");
        json.Should().Contain("\"commitShort\":\"a1b2c3d\"");
        json.Should().Contain("\"branches\":[\"main\"]");
        json.Should().Contain("\"stillPresent\":false");
    }

    [Fact]
    public void Map_all_preserves_input_order()
    {
        var findings = new List<Finding> { NewWorkingTree(), NewHistory(), NewCommitMessage() };

        var mapped = McpFindingMapper.MapAll(findings);

        mapped[0].Should().BeOfType<McpWorkingTreeFinding>();
        mapped[1].Should().BeOfType<McpHistoryFinding>();
        mapped[2].Should().BeOfType<McpCommitMessageFinding>();
    }

    [Fact]
    public void Mapped_history_finding_does_not_contain_email_shaped_string()
    {
        // Defensive: even if upstream redaction missed something, the mapped DTO has no
        // field that could legitimately carry an email, so any '@' is suspicious.
        var json = Serialise(McpFindingMapper.Map(NewHistory()));

        json.Should().NotContain("@");
    }

    private static Finding NewWorkingTree() => new Finding
    {
        Source = FindingSource.WorkingTree,
        File = "src/api.json",
        Line = 14,
        Column = 5,
        SecretType = "ConnectionString",
        Severity = Severity.Critical,
        Hint = "Password=***",
        Entropy = 3.8,
        SuggestedFix = "Move to dotnet user-secrets.",
    };

    private static HistoryFinding NewHistory() => new()
    {
        Source = FindingSource.History,
        File = "src/api.json",
        Line = 14,
        Column = 5,
        SecretType = "ConnectionString",
        Severity = Severity.Critical,
        Hint = "Password=***",
        Entropy = 3.8,
        SuggestedFix = "Rotate; rewrite history.",
        CommitSha = "a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2",
        CommitShort = "a1b2c3d",
        CommitDate = new DateTimeOffset(2024, 3, 15, 10, 23, 0, TimeSpan.Zero),
        AuthorName = "Jane Smith",
        Branches = new[] { "main" },
        StillPresent = false,
    };

    private static CommitMessageFinding NewCommitMessage() => new()
    {
        Source = FindingSource.CommitMessage,
        File = "<commit-message>",
        Line = 1,
        Column = 1,
        SecretType = "AwsAccessKey",
        Severity = Severity.Critical,
        Hint = "AwsAccessKey=***",
        Entropy = 4.0,
        SuggestedFix = "Rotate.",
        CommitSha = "deadbeefdeadbeefdeadbeefdeadbeefdeadbeef",
        CommitShort = "deadbee",
        CommitDate = new DateTimeOffset(2024, 5, 1, 0, 0, 0, TimeSpan.Zero),
        AuthorName = "Alex",
    };

    private static string Serialise(object value) => JsonSerializer.Serialize(value, Options);
}
