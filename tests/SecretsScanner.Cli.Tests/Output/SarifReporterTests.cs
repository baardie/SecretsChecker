using Newtonsoft.Json.Linq;
using SecretsScanner.Cli.Output;
using SecretsScanner.Core.Findings;

namespace SecretsScanner.Cli.Tests.Output;

/// <summary>
/// SARIF v2.1.0 output for GitHub Code Scanning, Azure DevOps, and any compliant viewer.
/// Severity → SARIF level mapping: critical/high → error, medium → warning, low → note.
/// </summary>
public sealed class SarifReporterTests
{
    [Fact]
    public void Tool_driver_metadata_is_populated()
    {
        var doc = ReportToJson(new[] { Make("ConnectionString", Severity.Critical) }, toolVersion: "1.2.3");

        var driver = doc["runs"]![0]!["tool"]!["driver"]!;
        driver["name"]!.Value<string>().Should().Be("dotnet-tool-secrets-scan");
        driver["version"]!.Value<string>().Should().Be("1.2.3");
        driver["semanticVersion"]!.Value<string>().Should().Be("1.2.3");
    }

    [Fact]
    public void Distinct_secret_types_become_distinct_rules()
    {
        var findings = new[]
        {
            Make("ConnectionString", Severity.Critical),
            Make("ConnectionString", Severity.Critical, file: "b.json"),
            Make("ApiKey", Severity.High),
        };

        var doc = ReportToJson(findings, "1.0.0");

        var rules = (JArray)doc["runs"]![0]!["tool"]!["driver"]!["rules"]!;
        var ruleIds = rules.Select(r => r["id"]!.Value<string>()).ToArray();
        ruleIds.Should().BeEquivalentTo(new[] { "ConnectionString", "ApiKey" });
    }

    [Theory]
    [InlineData(Severity.Critical, "error")]
    [InlineData(Severity.High, "error")]
    [InlineData(Severity.Medium, "warning")]
    [InlineData(Severity.Low, "note")]
    public void Severity_maps_to_sarif_level(Severity severity, string expectedLevel)
    {
        var doc = ReportToJson(new[] { Make("X", severity) }, "1.0.0");

        // Per SARIF v2.1.0 §3.27.10, an absent result.level implies "warning". Sarif.Sdk
        // omits the property when it equals that spec default.
        var level = doc["runs"]![0]!["results"]![0]!["level"]?.Value<string>() ?? "warning";
        level.Should().Be(expectedLevel);
    }

    [Fact]
    public void Result_carries_location_with_line_and_column()
    {
        var finding = Make("ConnectionString", Severity.Critical, file: "src/api.json", line: 14, column: 5);

        var doc = ReportToJson(new[] { finding }, "1.0.0");

        var location = doc["runs"]![0]!["results"]![0]!["locations"]![0]!["physicalLocation"]!;
        location["artifactLocation"]!["uri"]!.Value<string>().Should().Be("src/api.json");
        location["region"]!["startLine"]!.Value<int>().Should().Be(14);
        location["region"]!["startColumn"]!.Value<int>().Should().Be(5);
    }

    [Fact]
    public void Result_message_includes_hint_secret_type_and_suggested_fix()
    {
        var finding = Make("ConnectionString", Severity.Critical);

        var doc = ReportToJson(new[] { finding }, "1.0.0");

        var message = doc["runs"]![0]!["results"]![0]!["message"]!["text"]!.Value<string>();
        message.Should().Contain("Password=***");
        message.Should().Contain("ConnectionString");
        message.Should().Contain("Move to dotnet user-secrets");
    }

    [Fact]
    public void Empty_findings_produces_a_run_with_no_results_and_no_rules()
    {
        var doc = ReportToJson(Array.Empty<Finding>(), "1.0.0");

        var run = doc["runs"]![0]!;
        ((JArray?)run["results"])?.Count.Should().Be(0);
        var rules = (JArray?)run["tool"]!["driver"]!["rules"];
        // Sarif.Sdk emits an empty array; either null or zero-length is acceptable.
        (rules?.Count ?? 0).Should().Be(0);
    }

    private static Finding Make(
        string secretType,
        Severity severity,
        string file = "appsettings.json",
        int line = 14,
        int column = 5) =>
        new()
        {
            Source = FindingSource.WorkingTree,
            File = file,
            Line = line,
            Column = column,
            SecretType = secretType,
            Severity = severity,
            Hint = "Password=***",
            Entropy = 3.8,
            SuggestedFix = "Move to dotnet user-secrets.",
        };

    private static JObject ReportToJson(IReadOnlyList<Finding> findings, string toolVersion)
    {
        using var writer = new StringWriter();
        new SarifReporter(writer, toolVersion).Report(findings);
        return JObject.Parse(writer.ToString());
    }
}
