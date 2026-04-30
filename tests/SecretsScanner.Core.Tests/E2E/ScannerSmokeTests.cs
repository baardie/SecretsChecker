using SecretsScanner.Core;
using SecretsScanner.Core.Configuration;
using SecretsScanner.Core.Findings;

namespace SecretsScanner.Core.Tests.E2E;

/// <summary>
/// End-to-end smoke test: writes a fixture .NET-shaped project to a temp directory, runs the
/// scanner, and asserts both that seeded secrets are found and that no raw value appears in any
/// output. This is the M1 exit-criteria test.
/// </summary>
public sealed class ScannerSmokeTests : IDisposable
{
    private readonly string _root;

    public ScannerSmokeTests()
    {
        _root = Path.Combine(Path.GetTempPath(), $"secretsscan-{Guid.NewGuid():N}");
        Directory.CreateDirectory(_root);
    }

    [Fact]
    public void Detects_seeded_secrets_in_a_dotnet_project_layout()
    {
        var apiDir = Path.Combine(_root, "src", "Api");
        Directory.CreateDirectory(apiDir);

        // sk_live_ prefix kept separate from the suffix so this source file doesn't itself
        // trigger GitHub's push-protection scanner.
        var stripeKey = "sk_live_" + "abcdefghijklmnopqrstuvwx";
        File.WriteAllText(
            Path.Combine(apiDir, "appsettings.json"),
            $$"""
            {
              "ConnectionStrings": {
                "Default": "Server=db;Database=app;User Id=sa;Password=Pa$$w0rd!"
              },
              "Aws": {
                "AccessKeyId": "AKIAIOSFODNN7EXAMPLE"
              },
              "Stripe": {
                "ApiKey": "{{stripeKey}}"
              }
            }
            """);

        File.WriteAllText(
            Path.Combine(apiDir, "Program.cs"),
            """
            namespace Api;
            public static class Program
            {
                public static void Main()
                {
                    var token = "ghp_aaaabbbbccccddddeeeeffff0123456789AB";
                }
            }
            """);

        // Bin / obj should be skipped automatically.
        var binDir = Path.Combine(apiDir, "bin", "Debug");
        Directory.CreateDirectory(binDir);
        File.WriteAllText(Path.Combine(binDir, "secrets.json"),
            "\"Password\": \"shouldnotbedetected\"");

        // Placeholder should NOT trigger.
        File.WriteAllText(
            Path.Combine(apiDir, "appsettings.Example.json"),
            "{ \"Database\": { \"Password\": \"changeme\" } }");

        var scanner = new Scanner();
        var result = scanner.Scan(_root);

        result.Findings.Should().Contain(f => f.SecretType == "ConnectionString");
        result.Findings.Should().Contain(f => f.SecretType == "AwsAccessKey");
        result.Findings.Should().Contain(f => f.SecretType == "StripeKey");
        result.Findings.Should().Contain(f => f.SecretType == "GitHubToken");

        // Placeholder file must not match.
        result.Findings.Should().NotContain(f => f.File.Contains("Example.json"));

        // bin/ files must not be scanned.
        result.Findings.Should().NotContain(f => f.File.Contains("/bin/"));
    }

    [Fact]
    public void No_finding_contains_a_raw_secret_value()
    {
        var dir = Path.Combine(_root, "src");
        Directory.CreateDirectory(dir);

        // Split via concatenation so push-protection regex doesn't see the contiguous shape.
        const string realSecret = "sk_live_" + "abcdefghijklmnopqrstuvwx";
        File.WriteAllText(
            Path.Combine(dir, "Payments.cs"),
            $"public const string K = \"{realSecret}\";");

        var scanner = new Scanner();
        var result = scanner.Scan(_root);

        result.Findings.Should().NotBeEmpty();
        foreach (var finding in result.Findings)
        {
            // The raw secret must not appear in any string-valued public property.
            foreach (var prop in finding.GetType().GetProperties())
            {
                if (prop.PropertyType != typeof(string))
                {
                    continue;
                }

                var stringValue = (string?)prop.GetValue(finding);
                stringValue?.Contains(realSecret).Should().NotBe(true,
                    $"property {prop.Name} on a {finding.GetType().Name} must not contain the raw secret");
            }
        }
    }

    [Fact]
    public void Severity_threshold_filters_results()
    {
        var dir = Path.Combine(_root, "src");
        Directory.CreateDirectory(dir);

        // ApiKey is Medium severity — should be excluded by Critical threshold.
        File.WriteAllText(
            Path.Combine(dir, "appsettings.json"),
            """
            {
              "MyApiKey": "really-long-real-looking-key-12345"
            }
            """);

        var scanner = new Scanner();
        var critical = scanner.Scan(_root, ScannerOptions.Default with { MinimumSeverity = Severity.Critical });
        var medium = scanner.Scan(_root, ScannerOptions.Default with { MinimumSeverity = Severity.Medium });

        critical.Findings.Should().NotContain(f => f.SecretType == "ApiKey");
        medium.Findings.Should().Contain(f => f.SecretType == "ApiKey");
    }

    public void Dispose()
    {
        try
        {
            Directory.Delete(_root, recursive: true);
        }
        catch
        {
            // best effort — temp cleanup is not test-critical
        }
    }
}
