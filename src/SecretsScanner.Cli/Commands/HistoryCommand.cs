using LibGit2Sharp;
using SecretsScanner.Cli.Configuration;
using SecretsScanner.Cli.Output;
using SecretsScanner.Core;
using SecretsScanner.Core.Configuration;
using SecretsScanner.Core.Findings;

namespace SecretsScanner.Cli.Commands;

/// <summary>
/// The <c>history</c> verb. Walks commit history (per <see cref="GitHistoryOptions"/>),
/// applies the cap policy (Q8 — refuse to silently truncate beyond <c>--max-commits</c>),
/// applies the <c>--still-present-only</c> / <c>--removed-only</c> view filters, and emits
/// findings through the existing reporters. Exit codes match <see cref="ScanCommand"/>.
/// </summary>
public sealed class HistoryCommand
{
    public Task<int> ExecuteAsync(HistoryCliOptions options, CancellationToken cancellationToken)
    {
        try
        {
            return Task.FromResult(Run(options));
        }
        catch (Exception ex)
        {
            Console.Error.WriteLine($"error: {ex.GetType().Name}");
            return Task.FromResult(2);
        }
    }

    private static int Run(HistoryCliOptions cli)
    {
        if (!Directory.Exists(cli.Path) && !File.Exists(cli.Path))
        {
            Console.Error.WriteLine($"error: path not found: {cli.Path}");
            return 2;
        }

        if (cli.StillPresentOnly && cli.RemovedOnly)
        {
            Console.Error.WriteLine("error: --still-present-only and --removed-only are mutually exclusive");
            return 2;
        }

        var historyOptions = new GitHistoryOptions
        {
            Branch = cli.Branch,
            Since = cli.Since,
            MaxCommits = cli.AllHistory ? null : cli.MaxCommits,
            IncludeTags = !cli.NoTags,
            IncludeUnreachable = cli.IncludeUnreachable,
            ScanCommitMessages = !cli.NoScanCommitMessages,
        };

        // Cap policy (Q8): if there are more reachable commits than the cap, warn and require
        // --all-history rather than silently truncating.
        if (!cli.AllHistory && cli.MaxCommits is { } cap)
        {
            int reachable;
            try
            {
                reachable = new HistoryScanner().CountReachableCommits(cli.Path, historyOptions);
            }
            catch (RepositoryNotFoundException)
            {
                Console.Error.WriteLine($"error: not a git repository: {cli.Path}");
                return 2;
            }

            if (reachable > cap)
            {
                Console.Error.WriteLine(
                    $"warning: repository has {reachable} reachable commits, exceeding --max-commits {cap}. " +
                    "Re-run with --all-history to scan the full history, or raise --max-commits.");
                return 2;
            }
        }

        HistoryScanResult result;
        try
        {
            result = new HistoryScanner().Scan(
                cli.Path,
                historyOptions,
                new ScannerOptions
                {
                    MinimumSeverity = cli.Severity,
                    RedactPii = !cli.IncludePii,
                });
        }
        catch (RepositoryNotFoundException)
        {
            Console.Error.WriteLine($"error: not a git repository: {cli.Path}");
            return 2;
        }

        var findings = ApplyViewFilters(result.Findings, cli);
        Emit(cli, findings);

        return findings.Count == 0 ? 0 : 1;
    }

    private static IReadOnlyList<Finding> ApplyViewFilters(IReadOnlyList<Finding> findings, HistoryCliOptions cli)
    {
        if (!cli.StillPresentOnly && !cli.RemovedOnly)
        {
            return findings;
        }

        return findings.Where(f =>
        {
            if (f is HistoryFinding h)
            {
                return cli.StillPresentOnly ? h.StillPresent : !h.StillPresent;
            }

            // Commit-message findings have no working-tree counterpart by definition. They're
            // always history-only and pass the --removed-only filter; --still-present-only
            // drops them.
            return cli.RemovedOnly;
        }).ToList();
    }

    private static void Emit(HistoryCliOptions cli, IReadOnlyList<Finding> findings)
    {
        TextWriter writer = cli.Output is { } outputPath
            ? new StreamWriter(File.Create(outputPath))
            : Console.Out;

        try
        {
            switch (cli.Format)
            {
                case OutputFormat.Json:
                    new JsonReporter(writer, ScanCommand.ToolVersion).Report(findings);
                    break;
                case OutputFormat.Sarif:
                    new SarifReporter(writer, ScanCommand.ToolVersion).Report(findings);
                    break;
                case OutputFormat.Console:
                default:
                    var ansi = cli.Output is null
                        ? AnsiConsole.CreateForStdout(cli.Color)
                        : new AnsiConsole(writer, enabled: false);
                    new ConsoleReporter(ansi).Report(findings);
                    break;
            }
        }
        finally
        {
            if (cli.Output is not null)
            {
                writer.Flush();
                writer.Dispose();
            }
        }
    }
}

/// <summary>
/// CLI-side options for the <c>history</c> verb. Everything carrying through to the core is
/// translated into <see cref="GitHistoryOptions"/> and <see cref="ScannerOptions"/>; the rest
/// drives presentation and exit-policy.
/// </summary>
public sealed record HistoryCliOptions
{
    public string Path { get; init; } = "./";
    public string? Branch { get; init; }
    public DateTimeOffset? Since { get; init; }
    public int MaxCommits { get; init; } = 1000;
    public bool AllHistory { get; init; }
    public bool StillPresentOnly { get; init; }
    public bool RemovedOnly { get; init; }
    public bool NoTags { get; init; }
    public bool IncludeUnreachable { get; init; }
    public bool NoScanCommitMessages { get; init; }
    public OutputFormat Format { get; init; } = OutputFormat.Console;
    public Severity Severity { get; init; } = Severity.Medium;
    public string? Output { get; init; }
    public bool IncludePii { get; init; }
    public ColorMode Color { get; init; } = ColorMode.Auto;
}
