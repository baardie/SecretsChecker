using SecretsScanner.Cli.Baseline;
using SecretsScanner.Cli.Configuration;
using SecretsScanner.Cli.Hooks;
using SecretsScanner.Cli.Output;
using SecretsScanner.Cli.Watch;
using SecretsScanner.Core;
using SecretsScanner.Core.Findings;
using SecretsScanner.Core.Patterns;

namespace SecretsScanner.Cli.Commands;

/// <summary>
/// The default verb. Resolves the layered configuration, runs the scan (or one of the
/// hook-management actions), and emits findings via the chosen reporter. Exit codes follow
/// the PRD table: 0 (clean), 1 (findings), 2 (tool error).
/// </summary>
public sealed class ScanCommand
{
    public const string ToolVersion = "1.0.0";

    public async Task<int> ExecuteAsync(CliOptions cliOptions, CancellationToken cancellationToken)
    {
        try
        {
            if (cliOptions.UninstallHook)
            {
                return RunUninstallHook(cliOptions);
            }

            if (cliOptions.InstallHook)
            {
                return RunInstallHook(cliOptions);
            }

            if (cliOptions.Watch)
            {
                return await RunWatchAsync(cliOptions, cancellationToken).ConfigureAwait(false);
            }

            return RunScan(cliOptions);
        }
        catch (Exception ex)
        {
            Console.Error.WriteLine($"error: {ex.GetType().Name}");
            return 2;
        }
    }

    private static int RunScan(CliOptions cliOptions)
    {
        if (!Directory.Exists(cliOptions.Path) && !File.Exists(cliOptions.Path))
        {
            Console.Error.WriteLine($"error: path not found: {cliOptions.Path}");
            return 2;
        }

        var scanner = BuildScanner(cliOptions);
        var result = scanner.Scan(cliOptions.Path, cliOptions.ToScannerOptions());

        var findings = result.Findings;
        if (cliOptions.Baseline is { } baselinePath)
        {
            var baseline = new BaselineManager().Load(baselinePath);
            findings = new BaselineManager().Filter(findings, baseline);
        }

        if (cliOptions.WriteBaseline is { } writePath)
        {
            new BaselineManager().Save(writePath, findings, ToolVersion);
        }

        Emit(cliOptions, findings);

        return findings.Count == 0 ? 0 : 1;
    }

    private static async Task<int> RunWatchAsync(CliOptions cliOptions, CancellationToken cancellationToken)
    {
        var scanner = BuildScanner(cliOptions);

        Console.WriteLine($"Watching {cliOptions.Path} (press Ctrl+C to stop)...");
        using var runner = new WatchRunner(
            Path.GetFullPath(cliOptions.Path),
            scanner,
            cliOptions.ToScannerOptions(),
            (result, changedPath) =>
            {
                Console.WriteLine($"\n[{DateTime.Now:HH:mm:ss}] {changedPath}");
                Emit(cliOptions, result.Findings);
            });

        runner.Start();

        try
        {
            await Task.Delay(Timeout.Infinite, cancellationToken).ConfigureAwait(false);
        }
        catch (OperationCanceledException)
        {
            // graceful shutdown
        }

        return 0;
    }

    private static int RunInstallHook(CliOptions cliOptions)
    {
        var installer = new PreCommitHookInstaller(Path.GetFullPath(cliOptions.Path));
        var mode = cliOptions.ForceHook
            ? InstallMode.Force
            : cliOptions.AppendHook
                ? InstallMode.Append
                : InstallMode.Refuse;

        var result = installer.Install(mode);
        Console.WriteLine(result.Message);

        return result.Outcome switch
        {
            InstallOutcome.WroteFresh or InstallOutcome.AppendedToExisting or
            InstallOutcome.OverwroteWithBackup or InstallOutcome.AlreadyInstalled or
            InstallOutcome.DelegatedToKnownManager => 0,
            _ => 2,
        };
    }

    private static int RunUninstallHook(CliOptions cliOptions)
    {
        var installer = new PreCommitHookInstaller(Path.GetFullPath(cliOptions.Path));
        var result = installer.Uninstall();
        Console.WriteLine(result.Message);
        return 0;
    }

    private static Scanner BuildScanner(CliOptions cliOptions)
    {
        var library = PatternLibrary.CreateDefault(cliOptions.IncludeHighEntropy);
        return new Scanner(library);
    }

    private static void Emit(CliOptions cliOptions, IReadOnlyList<Finding> findings)
    {
        TextWriter writer = cliOptions.Output is { } outputPath
            ? new StreamWriter(File.Create(outputPath))
            : Console.Out;

        try
        {
            switch (cliOptions.Format)
            {
                case OutputFormat.Json:
                    new JsonReporter(writer, ToolVersion).Report(findings);
                    break;
                case OutputFormat.Sarif:
                    new SarifReporter(writer, ToolVersion).Report(findings);
                    break;
                case OutputFormat.Console:
                default:
                    var ansi = cliOptions.Output is null
                        ? AnsiConsole.CreateForStdout(cliOptions.Color)
                        : new AnsiConsole(writer, enabled: false);
                    new ConsoleReporter(ansi).Report(findings);
                    break;
            }
        }
        finally
        {
            if (cliOptions.Output is not null)
            {
                writer.Flush();
                writer.Dispose();
            }
        }
    }
}
