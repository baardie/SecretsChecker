using Microsoft.CodeAnalysis.Sarif;
using Newtonsoft.Json;
using SecretsScanner.Core.Findings;

namespace SecretsScanner.Cli.Output;

/// <summary>
/// SARIF reporter (R4 in plan §M2). Output is consumable by GitHub Code Scanning, Azure DevOps,
/// and any SARIF v2.1.0 viewer. Uses Microsoft's Sarif.Sdk.
/// </summary>
public sealed class SarifReporter
{
    private const string ToolName = "dotnet-tool-secrets-scan";
    private const string InformationUri = "https://github.com/baardie/SecretsChecker";

    private readonly TextWriter _output;
    private readonly string _toolVersion;

    public SarifReporter(TextWriter output, string toolVersion)
    {
        _output = output;
        _toolVersion = toolVersion;
    }

    public void Report(IReadOnlyList<Finding> findings)
    {
        var rules = findings
            .Select(f => f.SecretType)
            .Distinct(StringComparer.Ordinal)
            .Select(secretType => new ReportingDescriptor
            {
                Id = secretType,
                Name = secretType,
                ShortDescription = new MultiformatMessageString { Text = secretType },
                FullDescription = new MultiformatMessageString { Text = $"Detection rule for {secretType} secrets." },
                DefaultConfiguration = new ReportingConfiguration { Level = FailureLevel.Error },
            })
            .ToList();

        var run = new Run
        {
            Tool = new Tool
            {
                Driver = new ToolComponent
                {
                    Name = ToolName,
                    Version = _toolVersion,
                    SemanticVersion = _toolVersion,
                    InformationUri = new Uri(InformationUri),
                    Rules = rules,
                },
            },
            Results = findings.Select(ToResult).ToList(),
        };

        var log = new SarifLog
        {
            SchemaUri = new Uri("https://json.schemastore.org/sarif-2.1.0.json"),
            Version = SarifVersion.Current,
            Runs = new[] { run },
        };

        var json = JsonConvert.SerializeObject(log, new JsonSerializerSettings
        {
            Formatting = Formatting.Indented,
            NullValueHandling = NullValueHandling.Ignore,
        });
        _output.WriteLine(json);
    }

    private static Result ToResult(Finding f) => new()
    {
        RuleId = f.SecretType,
        Level = MapLevel(f.Severity),
        Message = new Message
        {
            Text = $"{f.Hint} ({f.SecretType}) — {f.SuggestedFix}",
        },
        Locations = new[]
        {
            new Location
            {
                PhysicalLocation = new PhysicalLocation
                {
                    ArtifactLocation = new ArtifactLocation
                    {
                        Uri = new Uri(f.File, UriKind.RelativeOrAbsolute),
                    },
                    Region = new Region
                    {
                        StartLine = f.Line,
                        StartColumn = f.Column,
                    },
                },
            },
        },
    };

    private static FailureLevel MapLevel(Severity severity) => severity switch
    {
        Severity.Critical => FailureLevel.Error,
        Severity.High => FailureLevel.Error,
        Severity.Medium => FailureLevel.Warning,
        Severity.Low => FailureLevel.Note,
        _ => FailureLevel.None,
    };
}
