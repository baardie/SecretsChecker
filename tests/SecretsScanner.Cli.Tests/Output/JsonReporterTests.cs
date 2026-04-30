using System.Text.Json;
using SecretsScanner.Cli.Output;
using SecretsScanner.Core.Findings;

namespace SecretsScanner.Cli.Tests.Output;

/// <summary>
/// R14 — JSON output is a versioned envelope. Working-tree, history, and commit-message
/// findings each emit their own additional fields; all enums are wire strings (camelCase),
/// no raw secret value reaches output.
/// </summary>
public sealed class JsonReporterTests
{
    [Fact]
    public void Empty_findings_emit_envelope_with_empty_array()
    {
        var doc = ReportToJson(Array.Empty<Finding>(), toolVersion: "9.9.9");

        doc.RootElement.GetProperty("schemaVersion").GetString().Should().Be("1");
        doc.RootElement.GetProperty("toolVersion").GetString().Should().Be("9.9.9");
        doc.RootElement.GetProperty("findings").GetArrayLength().Should().Be(0);
    }

    [Fact]
    public void Working_tree_finding_renders_with_camel_case_wire_strings()
    {
        var finding = new Finding
        {
            Source = FindingSource.WorkingTree,
            File = "src/Api/appsettings.Development.json",
            Line = 14,
            Column = 5,
            SecretType = "ConnectionString",
            Severity = Severity.Critical,
            Hint = "Password=***",
            Entropy = 3.8,
            SuggestedFix = "Move to dotnet user-secrets.",
        };

        var doc = ReportToJson(new[] { finding }, "1.0.0");

        var entry = doc.RootElement.GetProperty("findings")[0];
        entry.GetProperty("source").GetString().Should().Be("workingTree");
        entry.GetProperty("file").GetString().Should().Be("src/Api/appsettings.Development.json");
        entry.GetProperty("line").GetInt32().Should().Be(14);
        entry.GetProperty("column").GetInt32().Should().Be(5);
        entry.GetProperty("secretType").GetString().Should().Be("ConnectionString");
        entry.GetProperty("severity").GetString().Should().Be("critical");
        entry.GetProperty("hint").GetString().Should().Be("Password=***");
        entry.GetProperty("entropy").GetDouble().Should().Be(3.8);
        entry.GetProperty("suggestedFix").GetString().Should().Be("Move to dotnet user-secrets.");
    }

    [Fact]
    public void History_finding_includes_commit_metadata_and_still_present_flag()
    {
        var finding = new HistoryFinding
        {
            Source = FindingSource.History,
            File = "src/Api/appsettings.Development.json",
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
            Branches = new[] { "main", "release/1.0" },
            StillPresent = false,
        };

        var doc = ReportToJson(new[] { (Finding)finding }, "1.0.0");

        var entry = doc.RootElement.GetProperty("findings")[0];
        entry.GetProperty("source").GetString().Should().Be("history");
        entry.GetProperty("commitSha").GetString().Should().StartWith("a1b2c3d");
        entry.GetProperty("commitShort").GetString().Should().Be("a1b2c3d");
        entry.GetProperty("authorName").GetString().Should().Be("Jane Smith");
        entry.GetProperty("stillPresent").GetBoolean().Should().BeFalse();

        var branches = entry.GetProperty("branches").EnumerateArray().Select(b => b.GetString()).ToArray();
        branches.Should().Equal("main", "release/1.0");
    }

    [Fact]
    public void Commit_message_finding_renders_with_source_commitMessage()
    {
        var finding = new CommitMessageFinding
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

        var doc = ReportToJson(new[] { (Finding)finding }, "1.0.0");

        var entry = doc.RootElement.GetProperty("findings")[0];
        entry.GetProperty("source").GetString().Should().Be("commitMessage");
        entry.GetProperty("file").GetString().Should().Be("<commit-message>");
        entry.GetProperty("commitShort").GetString().Should().Be("deadbee");
        entry.TryGetProperty("stillPresent", out _).Should().BeFalse();
        entry.TryGetProperty("branches", out _).Should().BeFalse();
    }

    private static JsonDocument ReportToJson(IReadOnlyList<Finding> findings, string toolVersion)
    {
        using var writer = new StringWriter();
        new JsonReporter(writer, toolVersion).Report(findings);
        return JsonDocument.Parse(writer.ToString());
    }
}
