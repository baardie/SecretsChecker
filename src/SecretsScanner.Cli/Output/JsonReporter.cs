using System.Text.Json;
using System.Text.Json.Serialization;
using SecretsScanner.Core.Findings;

namespace SecretsScanner.Cli.Output;

/// <summary>
/// JSON reporter (R14). Emits a versioned envelope:
/// <c>{ "schemaVersion": "1", "toolVersion": "...", "findings": [...] }</c>.
/// Uses System.Text.Json — Newtonsoft is only present transitively via Sarif.Sdk.
/// </summary>
public sealed class JsonReporter
{
    private static readonly JsonSerializerOptions SerializerOptions = new()
    {
        WriteIndented = true,
        DefaultIgnoreCondition = JsonIgnoreCondition.WhenWritingNull,
        Converters = { new JsonStringEnumConverter(JsonNamingPolicy.CamelCase) },
        PropertyNamingPolicy = JsonNamingPolicy.CamelCase,
    };

    private readonly TextWriter _output;
    private readonly string _toolVersion;

    public JsonReporter(TextWriter output, string toolVersion)
    {
        _output = output;
        _toolVersion = toolVersion;
    }

    public void Report(IReadOnlyList<Finding> findings)
    {
        // Project to object so the serializer uses the runtime DTO type — preserves the
        // extra fields on HistoryFindingDto / CommitMessageFindingDto.
        var envelope = new JsonEnvelope
        {
            SchemaVersion = "1",
            ToolVersion = _toolVersion,
            Findings = findings.Select(f => (object)ToDto(f)).ToArray(),
        };

        var json = JsonSerializer.Serialize(envelope, SerializerOptions);
        _output.WriteLine(json);
    }

    private static FindingDto ToDto(Finding f) => f switch
    {
        HistoryFinding h => new HistoryFindingDto
        {
            Source = f.Source.ToWireString(),
            File = f.File,
            Line = f.Line,
            Column = f.Column,
            SecretType = f.SecretType,
            Severity = f.Severity.ToWireString(),
            Hint = f.Hint,
            Entropy = f.Entropy,
            SuggestedFix = f.SuggestedFix,
            CommitSha = h.CommitSha,
            CommitShort = h.CommitShort,
            CommitDate = h.CommitDate,
            AuthorName = h.AuthorName,
            Branches = h.Branches,
            StillPresent = h.StillPresent,
        },
        CommitMessageFinding c => new CommitMessageFindingDto
        {
            Source = f.Source.ToWireString(),
            File = f.File,
            Line = f.Line,
            Column = f.Column,
            SecretType = f.SecretType,
            Severity = f.Severity.ToWireString(),
            Hint = f.Hint,
            Entropy = f.Entropy,
            SuggestedFix = f.SuggestedFix,
            CommitSha = c.CommitSha,
            CommitShort = c.CommitShort,
            CommitDate = c.CommitDate,
            AuthorName = c.AuthorName,
        },
        Finding when f.GetType() == typeof(Finding) => new WorkingTreeFindingDto
        {
            Source = f.Source.ToWireString(),
            File = f.File,
            Line = f.Line,
            Column = f.Column,
            SecretType = f.SecretType,
            Severity = f.Severity.ToWireString(),
            Hint = f.Hint,
            Entropy = f.Entropy,
            SuggestedFix = f.SuggestedFix,
        },
        _ => throw new InvalidOperationException(
            $"Unhandled Finding subtype '{f.GetType().Name}' — JsonReporter must be updated when a new subtype is added."),
    };

    private sealed class JsonEnvelope
    {
        public required string SchemaVersion { get; init; }
        public required string ToolVersion { get; init; }
        public required IReadOnlyList<object> Findings { get; init; }
    }

    // The DTO hierarchy is closed and abstract: every Finding subtype maps to a concrete
    // sealed DTO. Making the base abstract prevents the `_ =>` branch in ToDto from quietly
    // instantiating a base-only DTO and dropping subtype fields.
    private abstract class FindingDto
    {
        public required string Source { get; init; }
        public required string File { get; init; }
        public required int Line { get; init; }
        public required int Column { get; init; }
        public required string SecretType { get; init; }
        public required string Severity { get; init; }
        public required string Hint { get; init; }
        public required double Entropy { get; init; }
        public required string SuggestedFix { get; init; }
    }

    private sealed class WorkingTreeFindingDto : FindingDto
    {
    }

    private sealed class HistoryFindingDto : FindingDto
    {
        public required string CommitSha { get; init; }
        public required string CommitShort { get; init; }
        public required DateTimeOffset CommitDate { get; init; }
        public required string AuthorName { get; init; }
        public required IReadOnlyList<string> Branches { get; init; }
        public required bool StillPresent { get; init; }
    }

    private sealed class CommitMessageFindingDto : FindingDto
    {
        public required string CommitSha { get; init; }
        public required string CommitShort { get; init; }
        public required DateTimeOffset CommitDate { get; init; }
        public required string AuthorName { get; init; }
    }
}
