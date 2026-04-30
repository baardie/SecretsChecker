using System.Text.Json;
using System.Text.Json.Serialization;
using SecretsScanner.Core.Findings;

namespace SecretsScanner.Cli.Baseline;

/// <summary>
/// Reads and writes a baseline file containing previously-acknowledged findings. Suppresses
/// baselined findings on subsequent runs. The baseline is committed (Q1) and safe to share —
/// it contains only <see cref="Finding"/> shape, no raw values.
///
/// Match key: <c>(File, Line, SecretType, Hint)</c>. Line drift forces a re-baseline by
/// design — easier to refresh than to silently miss new findings.
/// </summary>
public sealed class BaselineManager
{
    private static readonly JsonSerializerOptions SerializerOptions = new()
    {
        WriteIndented = true,
        PropertyNamingPolicy = JsonNamingPolicy.CamelCase,
        DefaultIgnoreCondition = JsonIgnoreCondition.WhenWritingNull,
    };

    public BaselineFile Load(string path)
    {
        if (!File.Exists(path))
        {
            return BaselineFile.Empty;
        }

        using var stream = File.OpenRead(path);
        var loaded = JsonSerializer.Deserialize<BaselineFile>(stream, SerializerOptions);
        return loaded ?? BaselineFile.Empty;
    }

    public void Save(string path, IReadOnlyList<Finding> findings, string toolVersion)
    {
        var entries = findings.Select(BaselineEntry.From).Distinct().ToArray();
        var file = new BaselineFile
        {
            SchemaVersion = "1",
            ToolVersion = toolVersion,
            Entries = entries,
        };

        var json = JsonSerializer.Serialize(file, SerializerOptions);

        var dir = Path.GetDirectoryName(Path.GetFullPath(path));
        if (!string.IsNullOrEmpty(dir))
        {
            Directory.CreateDirectory(dir);
        }

        File.WriteAllText(path, json);
    }

    public IReadOnlyList<Finding> Filter(IReadOnlyList<Finding> findings, BaselineFile baseline)
    {
        if (baseline.Entries.Count == 0)
        {
            return findings;
        }

        var keys = baseline.Entries.Select(e => e.Key).ToHashSet(StringComparer.Ordinal);
        return findings.Where(f => !keys.Contains(BaselineEntry.From(f).Key)).ToList();
    }
}

public sealed class BaselineFile
{
    public required string SchemaVersion { get; init; }
    public required string ToolVersion { get; init; }
    public required IReadOnlyList<BaselineEntry> Entries { get; init; }

    public static BaselineFile Empty { get; } = new()
    {
        SchemaVersion = "1",
        ToolVersion = "0.0.0",
        Entries = Array.Empty<BaselineEntry>(),
    };
}

public sealed record BaselineEntry
{
    public required string File { get; init; }
    public required int Line { get; init; }
    public required string SecretType { get; init; }
    public required string Hint { get; init; }

    [JsonIgnore]
    public string Key => $"{File}|{Line}|{SecretType}|{Hint}";

    public static BaselineEntry From(Finding finding) => new()
    {
        File = finding.File,
        Line = finding.Line,
        SecretType = finding.SecretType,
        Hint = finding.Hint,
    };
}
