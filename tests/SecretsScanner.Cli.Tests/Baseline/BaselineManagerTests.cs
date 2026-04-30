using System.Text.Json;
using SecretsScanner.Cli.Baseline;
using SecretsScanner.Core.Findings;

namespace SecretsScanner.Cli.Tests.Baseline;

/// <summary>
/// Q1 — baseline file is committed and contains only sanitised <see cref="Finding"/> shape
/// (no raw values). Match key per <see cref="BaselineEntry"/>: <c>(File, Line, SecretType,
/// Hint)</c>. Line drift forces a re-baseline by design.
/// </summary>
public sealed class BaselineManagerTests : IDisposable
{
    private readonly string _dir;

    public BaselineManagerTests()
    {
        _dir = Path.Combine(Path.GetTempPath(), "secrets-scan-baseline-tests-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(_dir);
    }

    public void Dispose()
    {
        try
        {
            if (Directory.Exists(_dir))
            {
                Directory.Delete(_dir, recursive: true);
            }
        }
        catch
        {
            // best effort
        }
    }

    [Fact]
    public void Save_then_load_round_trips_entries()
    {
        var path = Path.Combine(_dir, "baseline.json");
        var findings = new[]
        {
            FindingAt("a.json", 1, "ConnectionString", "Password=***"),
            FindingAt("b.json", 7, "ApiKey", "ApiKey=***"),
        };

        new BaselineManager().Save(path, findings, toolVersion: "1.2.3");

        var loaded = new BaselineManager().Load(path);
        loaded.SchemaVersion.Should().Be("1");
        loaded.ToolVersion.Should().Be("1.2.3");
        loaded.Entries.Should().HaveCount(2);
        loaded.Entries.Should().ContainEquivalentOf(new
        {
            File = "a.json",
            Line = 1,
            SecretType = "ConnectionString",
            Hint = "Password=***",
        });
        loaded.Entries.Should().ContainEquivalentOf(new
        {
            File = "b.json",
            Line = 7,
            SecretType = "ApiKey",
            Hint = "ApiKey=***",
        });
    }

    [Fact]
    public void Save_creates_parent_directories_when_missing()
    {
        var path = Path.Combine(_dir, "nested", "deeper", "baseline.json");

        new BaselineManager().Save(path, new[] { FindingAt("a.json", 1) }, "1.0.0");

        File.Exists(path).Should().BeTrue();
    }

    [Fact]
    public void Save_deduplicates_identical_match_keys()
    {
        var path = Path.Combine(_dir, "baseline.json");
        var findings = new[]
        {
            FindingAt("a.json", 1, "ConnectionString", "Password=***"),
            FindingAt("a.json", 1, "ConnectionString", "Password=***"),
            FindingAt("a.json", 1, "ConnectionString", "Password=***"),
        };

        new BaselineManager().Save(path, findings, "1.0.0");

        var loaded = new BaselineManager().Load(path);
        loaded.Entries.Should().HaveCount(1);
    }

    [Fact]
    public void Load_returns_empty_when_file_missing()
    {
        var path = Path.Combine(_dir, "does-not-exist.json");

        var loaded = new BaselineManager().Load(path);

        loaded.Should().BeSameAs(BaselineFile.Empty);
        loaded.Entries.Should().BeEmpty();
    }

    [Fact]
    public void Filter_suppresses_findings_matching_baseline()
    {
        var path = Path.Combine(_dir, "baseline.json");
        var findings = new[]
        {
            FindingAt("a.json", 1, "ConnectionString", "Password=***"),
            FindingAt("b.json", 7, "ApiKey", "ApiKey=***"),
        };
        new BaselineManager().Save(path, findings, "1.0.0");
        var baseline = new BaselineManager().Load(path);

        // Re-run produces the same two findings plus a brand-new one.
        var rerun = findings.Concat(new[] { FindingAt("c.json", 10, "JwtSecret", "JwtSecret=***") }).ToList();
        var filtered = new BaselineManager().Filter(rerun, baseline);

        filtered.Should().ContainSingle().Which.File.Should().Be("c.json");
    }

    [Fact]
    public void Filter_returns_input_unchanged_when_baseline_is_empty()
    {
        var input = new[] { FindingAt("a.json", 1) };

        var filtered = new BaselineManager().Filter(input, BaselineFile.Empty);

        filtered.Should().BeSameAs(input);
    }

    [Fact]
    public void Filter_does_not_match_when_line_drifts()
    {
        var path = Path.Combine(_dir, "baseline.json");
        new BaselineManager().Save(
            path,
            new[] { FindingAt("a.json", 1, "ConnectionString", "Password=***") },
            "1.0.0");
        var baseline = new BaselineManager().Load(path);

        var driftedSameFinding = new[] { FindingAt("a.json", 2, "ConnectionString", "Password=***") };
        var filtered = new BaselineManager().Filter(driftedSameFinding, baseline);

        filtered.Should().HaveCount(1, "line drift forces a re-baseline by design");
    }

    [Fact]
    public void Saved_baseline_contains_no_raw_secret_value_or_entropy()
    {
        var path = Path.Combine(_dir, "baseline.json");
        var findings = new[] { FindingAt("a.json", 1, "ConnectionString", "Password=***") };

        new BaselineManager().Save(path, findings, "1.0.0");

        var json = File.ReadAllText(path);
        // Sanity: only the four match-key fields and the envelope are emitted.
        using var doc = JsonDocument.Parse(json);
        var entry = doc.RootElement.GetProperty("entries")[0];
        entry.TryGetProperty("entropy", out _).Should().BeFalse();
        entry.TryGetProperty("value", out _).Should().BeFalse();
        entry.TryGetProperty("severity", out _).Should().BeFalse();
        entry.TryGetProperty("source", out _).Should().BeFalse();

        var keys = entry.EnumerateObject().Select(p => p.Name).ToArray();
        keys.Should().BeEquivalentTo(new[] { "file", "line", "secretType", "hint" });
    }

    private static Finding FindingAt(
        string file,
        int line,
        string secretType = "ConnectionString",
        string hint = "Password=***") =>
        new()
        {
            Source = FindingSource.WorkingTree,
            File = file,
            Line = line,
            Column = 1,
            SecretType = secretType,
            Severity = Severity.Critical,
            Hint = hint,
            Entropy = 3.84,
            SuggestedFix = "test fix",
        };
}
