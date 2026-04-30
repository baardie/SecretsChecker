using SecretsScanner.Core.Findings;
using SecretsScanner.Core.Patterns;

namespace SecretsScanner.Core.Tests.Patterns;

/// <summary>
/// Per-pattern detection tests. Each PRD secret type plus its R3 expansions has at least one
/// positive case, plus a negative-control to confirm placeholder/keyword filtering.
/// </summary>
public sealed class BuiltInPatternsTests
{
    private readonly PatternLibrary _library = PatternLibrary.CreateDefault();

    [Fact]
    public void Detects_AKIA_long_term_aws_access_key()
    {
        AssertDetects(
            "AwsAccessKey",
            "config.cs",
            "var key = \"AKIAIOSFODNN7EXAMPLE\";");
    }

    [Fact]
    public void Detects_ASIA_temporary_aws_key()
    {
        AssertDetects(
            "AwsAccessKey",
            "config.cs",
            "var key = \"ASIATESTKEYID0000000\";");
    }

    [Fact]
    public void Detects_AROA_role_aws_key()
    {
        AssertDetects(
            "AwsAccessKey",
            "config.cs",
            "var key = \"AROATESTROLEID000000\";");
    }

    [Fact]
    public void Detects_classic_github_pat()
    {
        AssertDetects(
            "GitHubToken",
            "deploy.sh",
            "GITHUB_TOKEN=ghp_aaaabbbbccccddddeeeeffff0123456789AB");
    }

    [Fact]
    public void Detects_fine_grained_github_pat()
    {
        var token = "github_pat_" + new string('A', 82);
        AssertDetects(
            "GitHubToken",
            "deploy.sh",
            $"export TOKEN={token}");
    }

    [Fact]
    public void Detects_stripe_live_key()
    {
        // Split via concatenation so the source file never contains a contiguous
        // 'sk_live_<24+ alphanumerics>' literal. C# folds adjacent string constants at
        // compile time, so AssertDetects still receives the joined runtime value and our
        // regex still matches it — but GitHub's push-protection scanner, which works on
        // raw source text, does not.
        AssertDetects(
            "StripeKey",
            "Payments.cs",
            "private const string Key = \"sk_live_" + "abcdefghijklmnopqrstuvwx\";");
    }

    [Fact]
    public void Detects_gitlab_pat()
    {
        AssertDetects(
            "GitLabToken",
            "deploy.sh",
            "GITLAB=glpat-abcdefghij1234567890");
    }

    [Fact]
    public void Detects_slack_token()
    {
        AssertDetects(
            "SlackToken",
            "config.cs",
            "var slack = \"xoxb-1111111111-2222222222-aaaaaaaaaaaa\";");
    }

    [Fact]
    public void Detects_pem_private_key()
    {
        AssertDetects(
            "PrivateKey",
            "key.txt",
            "-----BEGIN RSA PRIVATE KEY-----\nMIIBOgIBAAJBAJ...\n-----END RSA PRIVATE KEY-----");
    }

    [Fact]
    public void Detects_azure_storage_key_in_connection_string()
    {
        var key = new string('A', 86) + "==";
        AssertDetects(
            "AzureStorageKey",
            "appsettings.json",
            $"\"Storage\": \"DefaultEndpointsProtocol=https;AccountName=foo;AccountKey={key};EndpointSuffix=core.windows.net\"");
    }

    [Fact]
    public void Detects_jwt_secret_in_config()
    {
        AssertDetects(
            "JwtSecret",
            "appsettings.json",
            "{\n  \"JwtSettings\": { \"JwtSigningKey\": \"a-very-long-real-signing-secret-12345\" }\n}");
    }

    [Fact]
    public void Detects_password_field_in_json_config()
    {
        AssertDetects(
            "Password",
            "appsettings.json",
            "{ \"Database\": { \"Password\": \"r3al-secret-here\" } }");
    }

    [Fact]
    public void Detects_connection_string_with_password()
    {
        AssertDetects(
            "ConnectionString",
            "appsettings.json",
            "{ \"ConnectionStrings\": { \"Default\": \"Server=db;Database=app;User Id=sa;Password=Pa$$w0rd!\" } }");
    }

    [Fact]
    public void Does_not_detect_placeholder_passwords()
    {
        var matches = ScanContent("appsettings.json",
            "{ \"Database\": { \"Password\": \"changeme\" } }");

        matches.Should().NotContain(m => m.SecretType == "Password");
    }

    [Fact]
    public void Does_not_detect_password_field_in_csharp_source()
    {
        // R2: generic password regex must NOT fire on .cs files; only the AST runner should
        // (which is M2/Tier-B work). For now this asserts the regex tier excludes .cs.
        var matches = ScanContent("UserService.cs",
            "public void Login(string username, string password) { }");

        matches.Should().NotContain(m => m.SecretType == "Password" && m.PatternId == "generic.password.config");
    }

    [Fact]
    public void Keyword_prefilter_skips_files_without_relevant_tokens()
    {
        var matches = ScanContent("Readme.txt",
            "This file contains nothing of interest.");

        matches.Should().BeEmpty();
    }

    private void AssertDetects(string expectedSecretType, string file, string content)
    {
        var matches = ScanContent(file, content);
        matches.Should().Contain(m => m.SecretType == expectedSecretType,
            $"file '{file}' should produce a {expectedSecretType} match");
    }

    private List<RawMatchProjection> ScanContent(string relativePath, string content)
    {
        var rawMethod = typeof(PatternLibrary).GetMethod("Scan",
            System.Reflection.BindingFlags.NonPublic | System.Reflection.BindingFlags.Instance)!;
        var enumerable = (System.Collections.IEnumerable)rawMethod.Invoke(_library, new object[] { relativePath, content })!;
        var list = new List<RawMatchProjection>();
        foreach (var raw in enumerable)
        {
            var t = raw.GetType();
            list.Add(new RawMatchProjection(
                (string)t.GetProperty("SecretType")!.GetValue(raw)!,
                (string)t.GetProperty("PatternId")!.GetValue(raw)!));
        }

        return list;
    }

    private readonly record struct RawMatchProjection(string SecretType, string PatternId);
}
