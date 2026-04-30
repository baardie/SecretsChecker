using SecretsScanner.Core.Walking;

namespace SecretsScanner.Core.Tests.Walking;

public sealed class UnifiedDiffParserTests
{
    [Fact]
    public void Empty_or_null_input_yields_nothing()
    {
        UnifiedDiffParser.EnumerateAddedLines(string.Empty).Should().BeEmpty();
        UnifiedDiffParser.EnumerateAddedLines(null!).Should().BeEmpty();
    }

    [Fact]
    public void Pure_addition_yields_each_added_line_with_its_post_commit_number()
    {
        const string patch =
            "@@ -0,0 +1,3 @@\n" +
            "+first\n" +
            "+second\n" +
            "+third\n";

        var lines = UnifiedDiffParser.EnumerateAddedLines(patch).ToList();

        lines.Select(l => l.NewLineNumber).Should().Equal(1, 2, 3);
        lines.Select(l => l.Text).Should().Equal("first", "second", "third");
    }

    [Fact]
    public void Context_lines_advance_the_new_line_counter_but_are_not_emitted()
    {
        const string patch =
            "@@ -10,3 +10,4 @@\n" +
            " context-a\n" +
            " context-b\n" +
            "+inserted\n" +
            " context-c\n";

        var lines = UnifiedDiffParser.EnumerateAddedLines(patch).ToList();

        lines.Should().ContainSingle();
        lines[0].NewLineNumber.Should().Be(12);
        lines[0].Text.Should().Be("inserted");
    }

    [Fact]
    public void Deletion_lines_do_not_advance_the_new_line_counter()
    {
        const string patch =
            "@@ -1,3 +1,2 @@\n" +
            " keep\n" +
            "-removed\n" +
            "+added\n";

        var lines = UnifiedDiffParser.EnumerateAddedLines(patch).ToList();

        lines.Should().ContainSingle();
        lines[0].NewLineNumber.Should().Be(2);
        lines[0].Text.Should().Be("added");
    }

    [Fact]
    public void Multiple_hunks_reset_the_counter_per_hunk_header()
    {
        const string patch =
            "@@ -1,1 +1,1 @@\n" +
            "+at-line-1\n" +
            "@@ -50,1 +60,1 @@\n" +
            "+at-line-60\n";

        var lines = UnifiedDiffParser.EnumerateAddedLines(patch).ToList();

        lines.Should().HaveCount(2);
        lines[0].NewLineNumber.Should().Be(1);
        lines[1].NewLineNumber.Should().Be(60);
    }

    [Fact]
    public void Patch_header_lines_before_the_first_hunk_are_skipped()
    {
        const string patch =
            "diff --git a/file b/file\n" +
            "index 0000..ffff 100644\n" +
            "--- a/file\n" +
            "+++ b/file\n" +
            "@@ -0,0 +1,1 @@\n" +
            "+payload\n";

        var lines = UnifiedDiffParser.EnumerateAddedLines(patch).ToList();

        lines.Should().ContainSingle();
        lines[0].Text.Should().Be("payload");
    }

    [Fact]
    public void No_newline_marker_does_not_advance_the_counter()
    {
        const string patch =
            "@@ -0,0 +1,1 @@\n" +
            "+only-line\n" +
            "\\ No newline at end of file\n";

        var lines = UnifiedDiffParser.EnumerateAddedLines(patch).ToList();

        lines.Should().ContainSingle();
        lines[0].NewLineNumber.Should().Be(1);
    }

    [Fact]
    public void Hunk_header_with_single_line_count_form_parses_correctly()
    {
        // libgit2 uses the short form @@ -L +L @@ when the count is 1; both forms must work.
        const string patch =
            "@@ -1 +1 @@\n" +
            "+hello\n";

        var lines = UnifiedDiffParser.EnumerateAddedLines(patch).ToList();

        lines.Should().ContainSingle();
        lines[0].NewLineNumber.Should().Be(1);
    }
}
