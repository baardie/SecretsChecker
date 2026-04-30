using SecretsScanner.Core.Findings;

namespace SecretsScanner.Cli.Output;

/// <summary>
/// Default human-readable reporter. Wraps an <see cref="AnsiConsole"/> + <see cref="FindingTable"/>.
/// </summary>
public sealed class ConsoleReporter
{
    private readonly FindingTable _table;

    public ConsoleReporter(AnsiConsole console)
    {
        _table = new FindingTable(console);
    }

    public void Report(IReadOnlyList<Finding> findings) => _table.Render(findings);
}
