using SecretsScanner.Cli.Output;
using SecretsScanner.Core.Findings;

namespace SecretsScanner.Cli.Tests.Output;

/// <summary>
/// Human-readable reporter rendered through <see cref="FindingTable"/>. Findings group by
/// file, sort by line then column, and a summary line counts findings per severity. ANSI
/// codes appear only when colour is enabled.
/// </summary>
public sealed class ConsoleReporterTests
{
    [Fact]
    public void Empty_findings_render_no_findings_message()
    {
        var (text, _) = Render(Array.Empty<Finding>(), colour: false);

        text.Should().Contain("No findings.");
    }

    [Fact]
    public void Findings_group_by_file_and_sort_by_line_then_column()
    {
        var findings = new[]
        {
            FindingAt("b.json", 5, 10, "ApiKey", Severity.High),
            FindingAt("a.json", 14, 1, "ConnectionString", Severity.Critical),
            FindingAt("a.json", 2, 1, "Password", Severity.High),
        };

        var (text, _) = Render(findings, colour: false);

        // Group order alphabetical; within each file, sorted by line.
        var aIdx = text.IndexOf("a.json", StringComparison.Ordinal);
        var bIdx = text.IndexOf("b.json", StringComparison.Ordinal);
        aIdx.Should().BeGreaterOrEqualTo(0);
        bIdx.Should().BeGreaterThan(aIdx);

        var line2Idx = text.IndexOf("Password", StringComparison.Ordinal);
        var line14Idx = text.IndexOf("ConnectionString", StringComparison.Ordinal);
        line2Idx.Should().BeLessThan(line14Idx);
    }

    [Fact]
    public void Summary_counts_per_severity()
    {
        var findings = new[]
        {
            FindingAt("a.json", 1, 1, "X", Severity.Critical),
            FindingAt("a.json", 2, 1, "X", Severity.Critical),
            FindingAt("a.json", 3, 1, "X", Severity.High),
            FindingAt("a.json", 4, 1, "X", Severity.Medium),
            FindingAt("a.json", 5, 1, "X", Severity.Low),
        };

        var (text, _) = Render(findings, colour: false);

        text.Should().Contain("5 findings:");
        text.Should().Contain("2 critical");
        text.Should().Contain("1 high");
        text.Should().Contain("1 medium");
        text.Should().Contain("1 low");
    }

    [Fact]
    public void Single_finding_uses_singular_finding_label()
    {
        var (text, _) = Render(new[] { FindingAt("a.json", 1, 1, "X", Severity.High) }, colour: false);

        text.Should().Contain("1 finding:");
        text.Should().NotContain("1 findings:");
    }

    [Fact]
    public void Suggested_fix_is_rendered_when_present()
    {
        var (text, _) = Render(new[] { FindingAt("a.json", 1, 1, "X", Severity.High, fix: "Use dotnet user-secrets") }, colour: false);

        text.Should().Contain("Use dotnet user-secrets");
    }

    [Fact]
    public void Output_is_colour_free_when_colour_disabled()
    {
        var (text, _) = Render(new[] { FindingAt("a.json", 1, 1, "X", Severity.Critical) }, colour: false);

        text.Should().NotContain("\x1b[", "no ANSI escape sequences when colour is off");
    }

    [Fact]
    public void Output_contains_ansi_escapes_when_colour_enabled()
    {
        var (text, _) = Render(new[] { FindingAt("a.json", 1, 1, "X", Severity.Critical) }, colour: true);

        text.Should().Contain("\x1b[");
    }

    private static (string Text, int Lines) Render(IReadOnlyList<Finding> findings, bool colour)
    {
        var writer = new StringWriter();
        var console = new AnsiConsole(writer, enabled: colour);
        new ConsoleReporter(console).Report(findings);
        var text = writer.ToString();
        return (text, text.Count(c => c == '\n'));
    }

    private static Finding FindingAt(
        string file,
        int line,
        int column,
        string secretType,
        Severity severity,
        string fix = "test fix") =>
        new()
        {
            Source = FindingSource.WorkingTree,
            File = file,
            Line = line,
            Column = column,
            SecretType = secretType,
            Severity = severity,
            Hint = $"{secretType}=***",
            Entropy = 3.8,
            SuggestedFix = fix,
        };
}
