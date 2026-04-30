using System.CommandLine;
using System.CommandLine.Builder;
using System.CommandLine.Invocation;
using System.CommandLine.Parsing;
using SecretsScanner.Cli.Commands;
using SecretsScanner.Cli.Configuration;
using SecretsScanner.Cli.Output;
using SecretsScanner.Core.Findings;

namespace SecretsScanner.Cli;

internal static class Program
{
    public static async Task<int> Main(string[] args)
    {
        // UseDefaults wires help/version/suggestions; the same parser is used for both
        // pre-flight error detection and final invocation so directives like --help don't
        // look like unrecognised arguments.
        var parser = new CommandLineBuilder(BuildRootCommand())
            .UseDefaults()
            .Build();

        var parseResult = parser.Parse(args);

        // PRD exit-code table requires bad arguments to surface as exit 2 (tool error).
        // System.CommandLine's default is 1; convert here.
        if (parseResult.Errors.Count > 0)
        {
            foreach (var err in parseResult.Errors)
            {
                Console.Error.WriteLine($"error: {err.Message}");
            }
            return 2;
        }

        return await parser.InvokeAsync(args).ConfigureAwait(false);
    }

    internal static RootCommand BuildRootCommand()
    {
        var pathOption = new Option<string>(new[] { "--path", "-p" }, () => "./",
            "Path to scan (directory or file).");
        var formatOption = new Option<OutputFormat>(new[] { "--format", "-f" }, () => OutputFormat.Console,
            "Output format: console | json | sarif.");
        var severityOption = new Option<Severity>(new[] { "--severity", "-s" }, () => Severity.Medium,
            "Minimum severity to report.");
        var baselineOption = new Option<string?>("--baseline",
            "Path to a baseline file; matching findings are suppressed.");
        var writeBaselineOption = new Option<string?>("--write-baseline",
            "Write a fresh baseline file containing the current findings.");
        var watchOption = new Option<bool>("--watch",
            "Re-scan changed files in real time (300ms debounce).");
        var installHookOption = new Option<bool>("--install-hook",
            "Install a pre-commit hook (or print guidance if a known hook manager is in use).");
        var uninstallHookOption = new Option<bool>("--uninstall-hook",
            "Remove the pre-commit hook (only the marker block).");
        var forceOption = new Option<bool>("--force",
            "When installing the hook, overwrite an existing hook (a backup is written).");
        var appendOption = new Option<bool>("--append",
            "When installing the hook, append inside a marker block to an existing hook.");
        var outputOption = new Option<string?>(new[] { "--output", "-o" },
            "Write output to a file instead of stdout.");
        var includePiiOption = new Option<bool>("--include-pii",
            "Include PII fields (author name, user-home paths) in output. Default redacts.");
        var includeGeneratedOption = new Option<bool>("--include-generated",
            "Include generated files (Migrations, *.Designer.cs, etc.).");
        var includeHighEntropyOption = new Option<bool>("--include-high-entropy",
            "Enable the high-entropy heuristic detector (off by default).");
        var followSymlinksOption = new Option<bool>("--follow-symlinks",
            "Follow symlinks during traversal (off by default).");
        var maxFileSizeOption = new Option<long?>("--max-file-size",
            "Maximum file size in bytes; larger files are skipped.");
        var colorOption = new Option<ColorMode>("--color", () => ColorMode.Auto,
            "Colour output mode: auto | always | never.");
        var includeGlobOption = new Option<string[]>("--include",
            "Glob pattern(s) to include. Repeatable.")
        { AllowMultipleArgumentsPerToken = true };
        var excludeGlobOption = new Option<string[]>("--exclude",
            "Glob pattern(s) to exclude. Repeatable.")
        { AllowMultipleArgumentsPerToken = true };

        var root = new RootCommand("dotnet-tool-secrets-scan: detects hardcoded secrets in .NET projects.")
        {
            pathOption,
            formatOption,
            severityOption,
            baselineOption,
            writeBaselineOption,
            watchOption,
            installHookOption,
            uninstallHookOption,
            forceOption,
            appendOption,
            outputOption,
            includePiiOption,
            includeGeneratedOption,
            includeHighEntropyOption,
            followSymlinksOption,
            maxFileSizeOption,
            colorOption,
            includeGlobOption,
            excludeGlobOption,
        };

        root.AddCommand(BuildHistoryCommand(pathOption, formatOption, severityOption, outputOption, includePiiOption, colorOption));

        root.SetHandler(async (InvocationContext ctx) =>
        {
            var path = ctx.ParseResult.GetValueForOption(pathOption) ?? "./";
            var loader = new ConfigLoader();
            var fileOptions = loader.Load(path);

            var cliOptions = fileOptions with
            {
                Path = path,
                Format = ctx.ParseResult.GetValueForOption(formatOption),
                Severity = ctx.ParseResult.GetValueForOption(severityOption),
                Baseline = ctx.ParseResult.GetValueForOption(baselineOption) ?? fileOptions.Baseline,
                WriteBaseline = ctx.ParseResult.GetValueForOption(writeBaselineOption) ?? fileOptions.WriteBaseline,
                Watch = ctx.ParseResult.GetValueForOption(watchOption) || fileOptions.Watch,
                InstallHook = ctx.ParseResult.GetValueForOption(installHookOption) || fileOptions.InstallHook,
                UninstallHook = ctx.ParseResult.GetValueForOption(uninstallHookOption) || fileOptions.UninstallHook,
                ForceHook = ctx.ParseResult.GetValueForOption(forceOption) || fileOptions.ForceHook,
                AppendHook = ctx.ParseResult.GetValueForOption(appendOption) || fileOptions.AppendHook,
                Output = ctx.ParseResult.GetValueForOption(outputOption) ?? fileOptions.Output,
                IncludePii = ctx.ParseResult.GetValueForOption(includePiiOption) || fileOptions.IncludePii,
                IncludeGenerated = ctx.ParseResult.GetValueForOption(includeGeneratedOption) || fileOptions.IncludeGenerated,
                IncludeHighEntropy = ctx.ParseResult.GetValueForOption(includeHighEntropyOption) || fileOptions.IncludeHighEntropy,
                FollowSymlinks = ctx.ParseResult.GetValueForOption(followSymlinksOption) || fileOptions.FollowSymlinks,
                MaxFileSizeBytes = ctx.ParseResult.GetValueForOption(maxFileSizeOption) ?? fileOptions.MaxFileSizeBytes,
                Color = ctx.ParseResult.GetValueForOption(colorOption),
                Include = MergeGlobs(ctx.ParseResult.GetValueForOption(includeGlobOption), fileOptions.Include),
                Exclude = MergeGlobs(ctx.ParseResult.GetValueForOption(excludeGlobOption), fileOptions.Exclude),
            };

            ctx.ExitCode = await new ScanCommand().ExecuteAsync(cliOptions, ctx.GetCancellationToken()).ConfigureAwait(false);
        });

        return root;
    }

    private static IReadOnlyList<string> MergeGlobs(string[]? cliGlobs, IReadOnlyList<string> fileGlobs)
    {
        if (cliGlobs is null || cliGlobs.Length == 0)
        {
            return fileGlobs;
        }

        return cliGlobs;
    }

    private static Command BuildHistoryCommand(
        Option<string> pathOption,
        Option<OutputFormat> formatOption,
        Option<Severity> severityOption,
        Option<string?> outputOption,
        Option<bool> includePiiOption,
        Option<ColorMode> colorOption)
    {
        var branchOption = new Option<string?>("--branch", "Branch to scan; omit to walk all local branches.");
        var sinceOption = new Option<DateTimeOffset?>("--since", "ISO 8601 date; only scan commits at or after this instant.");
        var maxCommitsOption = new Option<int>("--max-commits", () => 1000, "Maximum number of commits (most-recent first).");
        var allHistoryOption = new Option<bool>("--all-history", "Scan the full reachable history, lifting the --max-commits cap.");
        var stillPresentOnlyOption = new Option<bool>("--still-present-only", "Only emit findings whose secret is also present in the working tree.");
        var removedOnlyOption = new Option<bool>("--removed-only", "Only emit findings whose secret has been removed from the working tree.");
        var noTagsOption = new Option<bool>("--no-tags", "Skip tag refs when enumerating commits.");
        var includeUnreachableOption = new Option<bool>("--include-unreachable", "Walk dangling / unreachable commits (slower).");
        var noScanCommitMessagesOption = new Option<bool>("--no-scan-commit-messages", "Do not apply the pattern library to commit message text.");

        var history = new Command("history",
            "Scan git commit history for hardcoded secrets. Reports location only — never values.")
        {
            pathOption,
            formatOption,
            severityOption,
            outputOption,
            includePiiOption,
            colorOption,
            branchOption,
            sinceOption,
            maxCommitsOption,
            allHistoryOption,
            stillPresentOnlyOption,
            removedOnlyOption,
            noTagsOption,
            includeUnreachableOption,
            noScanCommitMessagesOption,
        };

        history.SetHandler(async (InvocationContext ctx) =>
        {
            var cli = new HistoryCliOptions
            {
                Path = ctx.ParseResult.GetValueForOption(pathOption) ?? "./",
                Branch = ctx.ParseResult.GetValueForOption(branchOption),
                Since = ctx.ParseResult.GetValueForOption(sinceOption),
                MaxCommits = ctx.ParseResult.GetValueForOption(maxCommitsOption),
                AllHistory = ctx.ParseResult.GetValueForOption(allHistoryOption),
                StillPresentOnly = ctx.ParseResult.GetValueForOption(stillPresentOnlyOption),
                RemovedOnly = ctx.ParseResult.GetValueForOption(removedOnlyOption),
                NoTags = ctx.ParseResult.GetValueForOption(noTagsOption),
                IncludeUnreachable = ctx.ParseResult.GetValueForOption(includeUnreachableOption),
                NoScanCommitMessages = ctx.ParseResult.GetValueForOption(noScanCommitMessagesOption),
                Format = ctx.ParseResult.GetValueForOption(formatOption),
                Severity = ctx.ParseResult.GetValueForOption(severityOption),
                Output = ctx.ParseResult.GetValueForOption(outputOption),
                IncludePii = ctx.ParseResult.GetValueForOption(includePiiOption),
                Color = ctx.ParseResult.GetValueForOption(colorOption),
            };

            ctx.ExitCode = await new HistoryCommand().ExecuteAsync(cli, ctx.GetCancellationToken()).ConfigureAwait(false);
        });

        return history;
    }
}
