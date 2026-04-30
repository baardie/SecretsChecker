using SecretsScanner.Core.Findings;

namespace SecretsScanner.Cli.Output;

/// <summary>
/// Renders a list of <see cref="Finding"/>s to the console grouped by file. Severity is
/// colour-coded; column widths are fixed for stable, scannable output (R19).
/// </summary>
public sealed class FindingTable
{
    private readonly AnsiConsole _console;

    public FindingTable(AnsiConsole console)
    {
        _console = console;
    }

    public void Render(IReadOnlyList<Finding> findings)
    {
        if (findings.Count == 0)
        {
            _console.WriteLine("No findings.", AnsiStyle.Green);
            return;
        }

        var grouped = findings
            .GroupBy(f => f.File, StringComparer.Ordinal)
            .OrderBy(g => g.Key, StringComparer.Ordinal);

        foreach (var group in grouped)
        {
            _console.WriteLine();
            _console.WriteLine(group.Key, AnsiStyle.Bold);

            foreach (var f in group.OrderBy(f => f.Line).ThenBy(f => f.Column))
            {
                RenderFinding(f);
            }
        }

        _console.WriteLine();
        RenderSummary(findings);
    }

    private void RenderFinding(Finding f)
    {
        var location = $"  {f.Line,4}:{f.Column,-3}";
        _console.Write(location, AnsiStyle.Grey);
        _console.Write(" ");

        var severity = f.Severity.ToWireString();
        _console.Write($"{severity,-8}", StyleFor(f.Severity));
        _console.Write(" ");

        _console.Write($"{f.SecretType,-22}", AnsiStyle.Cyan);
        _console.Write(" ");

        _console.Write(f.Hint, AnsiStyle.Dim);
        _console.WriteLine();

        RenderHistoryDetails(f);

        if (!string.IsNullOrEmpty(f.SuggestedFix))
        {
            _console.Write("       ");
            _console.WriteLine($"\u2192 {f.SuggestedFix}", AnsiStyle.Grey);
        }
    }

    private void RenderHistoryDetails(Finding f)
    {
        switch (f)
        {
            case HistoryFinding h:
                _console.Write("       ");
                var stillPresentLabel = h.StillPresent ? "still present" : "removed from working tree";
                var branches = h.Branches.Count > 0 ? string.Join(", ", h.Branches) : "(detached)";
                _console.WriteLine(
                    $"\u2192 commit {h.CommitShort} {h.CommitDate:yyyy-MM-dd} [{branches}] - {stillPresentLabel}",
                    AnsiStyle.Grey);
                break;
            case CommitMessageFinding c:
                _console.Write("       ");
                _console.WriteLine(
                    $"\u2192 commit {c.CommitShort} {c.CommitDate:yyyy-MM-dd} (commit message)",
                    AnsiStyle.Grey);
                break;
        }
    }

    private void RenderSummary(IReadOnlyList<Finding> findings)
    {
        var counts = findings
            .GroupBy(f => f.Severity)
            .ToDictionary(g => g.Key, g => g.Count());

        var critical = counts.GetValueOrDefault(Severity.Critical);
        var high = counts.GetValueOrDefault(Severity.High);
        var medium = counts.GetValueOrDefault(Severity.Medium);
        var low = counts.GetValueOrDefault(Severity.Low);

        _console.Write($"{findings.Count} finding{(findings.Count == 1 ? string.Empty : "s")}: ", AnsiStyle.Bold);
        _console.Write($"{critical} critical", AnsiStyle.BoldRed);
        _console.Write(", ");
        _console.Write($"{high} high", AnsiStyle.Red);
        _console.Write(", ");
        _console.Write($"{medium} medium", AnsiStyle.Yellow);
        _console.Write(", ");
        _console.WriteLine($"{low} low", AnsiStyle.Grey);
    }

    private static AnsiStyle StyleFor(Severity severity) => severity switch
    {
        Severity.Critical => AnsiStyle.BoldRed,
        Severity.High => AnsiStyle.Red,
        Severity.Medium => AnsiStyle.Yellow,
        Severity.Low => AnsiStyle.Grey,
        _ => AnsiStyle.Grey,
    };
}
