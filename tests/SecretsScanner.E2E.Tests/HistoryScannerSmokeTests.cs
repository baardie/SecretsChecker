using SecretsScanner.Core;
using SecretsScanner.Core.Configuration;
using SecretsScanner.Core.Findings;
using SecretsScanner.E2E.Tests.Fixtures;
using CoreFindings = SecretsScanner.Core.Findings;

namespace SecretsScanner.E2E.Tests;

/// <summary>
/// End-to-end coverage for <see cref="HistoryScanner"/>. Each test builds a real on-disk
/// repository via LibGit2Sharp and asserts the produced <see cref="HistoryFinding"/> /
/// <see cref="CommitMessageFinding"/> set against the M3 plan's scenario list.
/// </summary>
public sealed class HistoryScannerSmokeTests
{
    private const string AwsKey = "AKIAIOSFODNN7EXAMPLE";
    private const string OtherAwsKey = "AKIA0000000000000000";

    [Fact]
    public void Secret_added_in_commit_A_emits_a_HistoryFinding_with_stillPresent_true()
    {
        using var fixture = new FixtureRepo();
        fixture.Commit("seed", ("src/Program.cs", "Console.WriteLine(\"hi\");"));
        var commitA = fixture.Commit("leak", ("src/Program.cs", $"var key = \"{AwsKey}\";"));

        var result = new HistoryScanner().Scan(fixture.Path, GitHistoryOptions.Default);

        var leak = result.Findings.OfType<HistoryFinding>().Should().ContainSingle().Which;
        leak.SecretType.Should().Be("AwsAccessKey");
        leak.CommitSha.Should().Be(commitA.Sha);
        leak.File.Should().Be("src/Program.cs");
        leak.StillPresent.Should().BeTrue();
        leak.AuthorName.Should().Be(CoreFindings.Redaction.RedactedAuthor, "PII redaction is on by default (R8)");
        leak.Branches.Should().NotBeEmpty();
    }

    [Fact]
    public void Secret_added_in_A_then_removed_in_B_has_stillPresent_false()
    {
        using var fixture = new FixtureRepo();
        fixture.Commit("seed", ("src/Program.cs", "Console.WriteLine(\"hi\");"));
        var commitA = fixture.Commit("leak", ("src/Program.cs", $"var key = \"{AwsKey}\";"));
        fixture.Commit("clean", ("src/Program.cs", "Console.WriteLine(\"hi\");"));

        var result = new HistoryScanner().Scan(fixture.Path, GitHistoryOptions.Default);

        var leak = result.Findings.OfType<HistoryFinding>().Should().ContainSingle().Which;
        leak.CommitSha.Should().Be(commitA.Sha);
        leak.StillPresent.Should().BeFalse("the secret was removed from the working tree but lives on in history");
    }

    [Fact]
    public void Same_commit_visible_from_two_branches_lists_both_branches()
    {
        using var fixture = new FixtureRepo();
        fixture.Commit("seed", ("src/Program.cs", "Console.WriteLine(\"hi\");"));
        var commitA = fixture.Commit("leak", ("src/Program.cs", $"var key = \"{AwsKey}\";"));

        // A second branch points at the same leaking commit.
        fixture.CreateBranch("feature/bug-fix", commitA);

        var result = new HistoryScanner().Scan(fixture.Path, GitHistoryOptions.Default);

        var leak = result.Findings.OfType<HistoryFinding>().Should().ContainSingle().Which;
        leak.Branches.Should().Contain("feature/bug-fix");
        leak.Branches.Should().HaveCount(2, "the commit is reachable from both the default branch and the feature branch");
    }

    [Fact]
    public void Parent_less_first_commit_with_a_secret_is_diffed_against_the_empty_tree()
    {
        using var fixture = new FixtureRepo();
        var commitA = fixture.Commit("initial", ("config.cs", $"var k = \"{AwsKey}\";"));

        var result = new HistoryScanner().Scan(fixture.Path, GitHistoryOptions.Default);

        var leak = result.Findings.OfType<HistoryFinding>().Should().ContainSingle().Which;
        leak.CommitSha.Should().Be(commitA.Sha);
    }

    [Fact]
    public void Same_secret_in_two_commits_dedups_to_the_earliest_commit()
    {
        using var fixture = new FixtureRepo();
        var commitA = fixture.Commit("first leak", ("a.cs", $"var k = \"{AwsKey}\";"));
        fixture.Commit("re-leak", ("a.cs", "// removed"));
        fixture.Commit("re-introduce", ("b.cs", $"var k = \"{AwsKey}\";"));

        var result = new HistoryScanner().Scan(fixture.Path, GitHistoryOptions.Default);

        result.Findings.OfType<HistoryFinding>().Should().ContainSingle()
            .Which.CommitSha.Should().Be(commitA.Sha, "dedup keeps the earliest introduction (plan §M3 dedup rule)");
    }

    [Fact]
    public void Distinct_secret_values_each_emit_their_own_finding()
    {
        using var fixture = new FixtureRepo();
        fixture.Commit("first", ("a.cs", $"var k = \"{AwsKey}\";"));
        fixture.Commit("second", ("b.cs", $"var k = \"{OtherAwsKey}\";"));

        var result = new HistoryScanner().Scan(fixture.Path, GitHistoryOptions.Default);

        result.Findings.OfType<HistoryFinding>().Should().HaveCount(2);
    }

    [Fact]
    public void Commit_message_with_a_secret_emits_a_CommitMessageFinding()
    {
        using var fixture = new FixtureRepo();
        fixture.Commit($"chore: rotate {AwsKey}", ("README.md", "# project"));

        var result = new HistoryScanner().Scan(fixture.Path, GitHistoryOptions.Default);

        var msg = result.Findings.OfType<CommitMessageFinding>().Should().ContainSingle().Which;
        msg.SecretType.Should().Be("AwsAccessKey");
        msg.File.Should().Be("<commit-message>");
        msg.AuthorName.Should().Be(CoreFindings.Redaction.RedactedAuthor);
    }

    [Fact]
    public void Commit_messages_can_be_opted_out_of_scanning()
    {
        using var fixture = new FixtureRepo();
        fixture.Commit($"chore: rotate {AwsKey}", ("README.md", "# project"));

        var result = new HistoryScanner().Scan(
            fixture.Path,
            GitHistoryOptions.Default with { ScanCommitMessages = false });

        result.Findings.OfType<CommitMessageFinding>().Should().BeEmpty();
    }

    [Fact]
    public void Tag_only_commit_is_found_by_default_and_skipped_with_no_tags()
    {
        using var fixture = new FixtureRepo();
        var safeCommit = fixture.Commit("seed", ("src/Program.cs", "Console.WriteLine(\"hi\");"));
        var leakCommit = fixture.Commit("leak", ("src/Program.cs", $"var key = \"{AwsKey}\";"));

        // Tag the leaking commit, then move HEAD back so the leak is reachable only via tag.
        fixture.CreateTag("v1.0", leakCommit);
        fixture.Repository.Reset(LibGit2Sharp.ResetMode.Hard, safeCommit);

        new HistoryScanner().Scan(fixture.Path, GitHistoryOptions.Default).Findings
            .OfType<HistoryFinding>().Should().ContainSingle()
            .Which.CommitSha.Should().Be(leakCommit.Sha);

        new HistoryScanner().Scan(fixture.Path, GitHistoryOptions.Default with { IncludeTags = false }).Findings
            .OfType<HistoryFinding>().Should().BeEmpty();
    }

    [Fact]
    public void Dangling_commit_is_skipped_by_default_and_found_with_include_unreachable()
    {
        using var fixture = new FixtureRepo();
        fixture.Commit("seed", ("README.md", "# project"));
        fixture.CreateOrphanCommit("dangling", ("orphan.cs", $"var k = \"{AwsKey}\";"));

        new HistoryScanner().Scan(fixture.Path, GitHistoryOptions.Default).Findings
            .OfType<HistoryFinding>().Should().BeEmpty();

        new HistoryScanner().Scan(fixture.Path, GitHistoryOptions.Default with { IncludeUnreachable = true }).Findings
            .OfType<HistoryFinding>().Should().ContainSingle()
            .Which.SecretType.Should().Be("AwsAccessKey");
    }

    [Fact]
    public void Severity_filter_drops_findings_below_threshold()
    {
        using var fixture = new FixtureRepo();
        fixture.Commit("seed", ("src/Program.cs", "Console.WriteLine(\"hi\");"));
        fixture.Commit("leak", ("src/Program.cs", $"var key = \"{AwsKey}\";"));

        var result = new HistoryScanner().Scan(
            fixture.Path,
            GitHistoryOptions.Default,
            new ScannerOptions { MinimumSeverity = Severity.Critical });

        // AwsAccessKey is Critical so it survives; assert no spurious lower-sev noise.
        result.Findings.OfType<HistoryFinding>()
            .Should().OnlyContain(f => f.Severity == Severity.Critical);
    }

    [Fact]
    public void No_secret_anywhere_returns_empty_result()
    {
        using var fixture = new FixtureRepo();
        fixture.Commit("seed", ("README.md", "# project"));
        fixture.Commit("more", ("src/Program.cs", "Console.WriteLine(\"clean\");"));

        var result = new HistoryScanner().Scan(fixture.Path, GitHistoryOptions.Default);

        result.Findings.Should().BeEmpty();
        result.CommitsWalked.Should().Be(2);
    }
}
