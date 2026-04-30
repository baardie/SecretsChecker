using SecretsScanner.Core.Findings;

namespace SecretsScanner.Core.Tests.Findings;

public sealed class RedactionTests
{
    [Theory]
    [InlineData("/Users/jane/code/proj/file.cs", "~/code/proj/file.cs")]
    [InlineData("/home/jane/code/proj/file.cs", "~/code/proj/file.cs")]
    [InlineData(@"C:\Users\jane\code\proj\file.cs", "~/code/proj/file.cs")]
    [InlineData(@"D:\Users\jane\code\proj\file.cs", "~/code/proj/file.cs")]
    public void Home_paths_are_redacted_to_tilde(string input, string expected)
    {
        Redaction.RedactHomePath(input).Should().Be(expected);
    }

    [Fact]
    public void Non_home_paths_are_preserved()
    {
        Redaction.RedactHomePath("src/Api/appsettings.json")
            .Should().Be("src/Api/appsettings.json");
    }

    [Fact]
    public void Apply_redacts_history_finding_author_and_path()
    {
        var finding = new HistoryFinding
        {
            Source = FindingSource.History,
            File = "/Users/jane/code/proj/appsettings.json",
            Line = 14,
            Column = 5,
            SecretType = "ConnectionString",
            Severity = Severity.Critical,
            Hint = "Password=***",
            Entropy = 4.2,
            SuggestedFix = "rotate",
            CommitSha = "a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2",
            CommitShort = "a1b2c3d",
            CommitDate = DateTimeOffset.UtcNow,
            AuthorName = "Jane Smith",
            Branches = new[] { "main" },
            StillPresent = false,
        };

        var redacted = (HistoryFinding)Redaction.Apply(finding, redactPii: true);

        redacted.AuthorName.Should().Be(Redaction.RedactedAuthor);
        redacted.File.Should().Be("~/code/proj/appsettings.json");
    }

    [Fact]
    public void Apply_with_redactPii_false_passes_through()
    {
        var finding = new Finding
        {
            Source = FindingSource.WorkingTree,
            File = "/Users/jane/code/proj/x.cs",
            Line = 1,
            Column = 1,
            SecretType = "Password",
            Severity = Severity.High,
            Hint = "Password=***",
            Entropy = 3.0,
            SuggestedFix = "x",
        };

        var passthrough = Redaction.Apply(finding, redactPii: false);

        passthrough.File.Should().Be(finding.File);
    }
}
