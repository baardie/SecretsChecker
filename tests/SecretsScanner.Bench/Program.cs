using System.Diagnostics;
using BenchmarkDotNet.Running;
using SecretsScanner.Bench.Fixtures;
using SecretsScanner.Core;
using SecretsScanner.Core.Configuration;

namespace SecretsScanner.Bench;

/// <summary>
/// Entry point. <c>validate</c> is a quick (≤ 1 minute) self-test that builds the fixtures
/// and runs each scan once, printing elapsed wall-clock time so the harness can be sanity-
/// checked without waiting for a full BenchmarkDotNet run. Any other args go straight to
/// <see cref="BenchmarkSwitcher"/> for proper measured runs.
/// </summary>
internal static class Program
{
    public static int Main(string[] args)
    {
        if (args.Length > 0 && string.Equals(args[0], "validate", StringComparison.OrdinalIgnoreCase))
        {
            return RunValidate(args.Skip(1).ToArray());
        }

        BenchmarkSwitcher.FromAssembly(typeof(Program).Assembly).Run(args);
        return 0;
    }

    private static int RunValidate(string[] args)
    {
        var fileCount = ParseInt(args, "--files", 1000);
        var commitCount = ParseInt(args, "--commits", 1000);

        Console.WriteLine($"VALIDATE: working-tree {fileCount} files | history {commitCount} commits");

        var wtRoot = Path.Combine(Path.GetTempPath(), "secrets-bench-validate-wt-" + Guid.NewGuid().ToString("N"));
        var histRoot = Path.Combine(Path.GetTempPath(), "secrets-bench-validate-hist-" + Guid.NewGuid().ToString("N"));

        try
        {
            var build = Stopwatch.StartNew();
            WorkingTreeFixture.Build(wtRoot, fileCount);
            build.Stop();
            Console.WriteLine($"  built working-tree fixture in {build.Elapsed.TotalSeconds:F2}s");

            var scan = Stopwatch.StartNew();
            var wtResult = new Scanner().Scan(wtRoot);
            scan.Stop();
            Console.WriteLine(
                $"  working-tree scan: {scan.Elapsed.TotalSeconds:F2}s, " +
                $"{wtResult.Findings.Count} findings, target < 10s ({Verdict(scan.Elapsed.TotalSeconds, 10)})");

            build.Restart();
            HistoryFixture.Build(histRoot, commitCount);
            build.Stop();
            Console.WriteLine($"  built history fixture in {build.Elapsed.TotalSeconds:F2}s");

            scan.Restart();
            var histResult = new HistoryScanner().Scan(histRoot, GitHistoryOptions.Default with { MaxCommits = null });
            scan.Stop();
            var historyTarget = commitCount >= 1000 ? 30 : 30 * commitCount / 1000.0;
            Console.WriteLine(
                $"  history scan: {scan.Elapsed.TotalSeconds:F2}s, " +
                $"{histResult.Findings.Count} findings, {histResult.CommitsWalked} commits walked, " +
                $"target < {historyTarget:F1}s ({Verdict(scan.Elapsed.TotalSeconds, historyTarget)})");

            return 0;
        }
        finally
        {
            TryDelete(wtRoot);
            TryDelete(histRoot);
        }
    }

    private static string Verdict(double actual, double target) => actual <= target ? "PASS" : "FAIL";

    private static int ParseInt(string[] args, string flag, int fallback)
    {
        for (var i = 0; i < args.Length - 1; i++)
        {
            if (string.Equals(args[i], flag, StringComparison.OrdinalIgnoreCase) &&
                int.TryParse(args[i + 1], out var value))
            {
                return value;
            }
        }
        return fallback;
    }

    private static void TryDelete(string path)
    {
        try
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
        catch
        {
            // best effort
        }
    }
}
