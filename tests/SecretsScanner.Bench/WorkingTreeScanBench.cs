using BenchmarkDotNet.Attributes;
using SecretsScanner.Bench.Fixtures;
using SecretsScanner.Core;

namespace SecretsScanner.Bench;

/// <summary>
/// R10 — working-tree scan target: &lt; 10 s on a typical .NET solution (&lt; 5 000 source
/// files, &lt; 500 k LOC, warm OS cache). The 100/1000-file params bracket that ceiling.
/// </summary>
[MemoryDiagnoser]
public class WorkingTreeScanBench
{
    [Params(100, 1000)]
    public int FileCount { get; set; }

    private string _root = string.Empty;
    private Scanner _scanner = null!;

    [GlobalSetup]
    public void Setup()
    {
        _root = Path.Combine(Path.GetTempPath(), "secrets-bench-wt-" + Guid.NewGuid().ToString("N"));
        WorkingTreeFixture.Build(_root, FileCount);
        _scanner = new Scanner();
    }

    [Benchmark]
    public int Scan() => _scanner.Scan(_root).Findings.Count;

    [GlobalCleanup]
    public void Cleanup()
    {
        try
        {
            if (Directory.Exists(_root))
            {
                Directory.Delete(_root, recursive: true);
            }
        }
        catch
        {
            // best-effort temp cleanup
        }
    }
}
