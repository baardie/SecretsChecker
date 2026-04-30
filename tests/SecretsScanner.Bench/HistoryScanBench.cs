using BenchmarkDotNet.Attributes;
using SecretsScanner.Bench.Fixtures;
using SecretsScanner.Core;
using SecretsScanner.Core.Configuration;

namespace SecretsScanner.Bench;

/// <summary>
/// R10 — history scan target: &lt; 30 s for 1 000 commits with average commit &lt; 500 added
/// lines. The 100/1000 params bracket that. With <see cref="GitHistoryOptions.MaxCommits"/>
/// = null we lift the cap so the full fixture is walked.
/// </summary>
[MemoryDiagnoser]
public class HistoryScanBench
{
    [Params(100, 1000)]
    public int CommitCount { get; set; }

    private string _root = string.Empty;
    private GitHistoryOptions _options = null!;
    private HistoryScanner _scanner = null!;

    [GlobalSetup]
    public void Setup()
    {
        _root = Path.Combine(Path.GetTempPath(), "secrets-bench-hist-" + Guid.NewGuid().ToString("N"));
        HistoryFixture.Build(_root, CommitCount);
        _options = GitHistoryOptions.Default with { MaxCommits = null };
        _scanner = new HistoryScanner();
    }

    [Benchmark]
    public int Scan() => _scanner.Scan(_root, _options).Findings.Count;

    [GlobalCleanup]
    public void Cleanup()
    {
        try
        {
            if (Directory.Exists(_root))
            {
                ForceDelete(_root);
            }
        }
        catch
        {
            // best-effort temp cleanup
        }
    }

    private static void ForceDelete(string path)
    {
        // libgit2 leaves some pack files read-only on Windows; clear attributes before delete.
        foreach (var file in Directory.EnumerateFiles(path, "*", SearchOption.AllDirectories))
        {
            try { File.SetAttributes(file, FileAttributes.Normal); } catch { /* ignore */ }
        }
        Directory.Delete(path, recursive: true);
    }
}
