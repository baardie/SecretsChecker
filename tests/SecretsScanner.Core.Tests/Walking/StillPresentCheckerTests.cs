using SecretsScanner.Core.Findings;
using SecretsScanner.Core.Walking;

namespace SecretsScanner.Core.Tests.Walking;

public sealed class StillPresentCheckerTests
{
    [Fact]
    public void Empty_set_means_never_still_present()
    {
        var history = NewRaw("AKIAEXAMPLEEXAMPLE00", "AwsAccessKey");

        StillPresentChecker.Empty.IsStillPresent(history).Should().BeFalse();
    }

    [Fact]
    public void Same_secret_type_and_value_is_still_present()
    {
        var current = NewRaw("hunter2", "Password");
        var history = NewRaw("hunter2", "Password");

        var checker = new StillPresentChecker(new[] { current });

        checker.IsStillPresent(history).Should().BeTrue();
    }

    [Fact]
    public void Different_value_is_not_still_present()
    {
        var current = NewRaw("hunter2", "Password");
        var history = NewRaw("hunter3", "Password");

        var checker = new StillPresentChecker(new[] { current });

        checker.IsStillPresent(history).Should().BeFalse();
    }

    [Fact]
    public void Same_value_under_a_different_secret_type_is_not_still_present()
    {
        // Type-scoping guards against cross-pattern collisions: a literal that happens to look
        // like a Password to one detector and an ApiKey to another shouldn't be treated as the
        // same finding.
        var current = NewRaw("AKIAEXAMPLEEXAMPLE00", "AwsAccessKey");
        var history = NewRaw("AKIAEXAMPLEEXAMPLE00", "ApiKey");

        var checker = new StillPresentChecker(new[] { current });

        checker.IsStillPresent(history).Should().BeFalse();
    }

    [Fact]
    public void File_path_does_not_affect_stillPresent()
    {
        // Renames don't break the link.
        var current = NewRaw("hunter2", "Password", file: "src/old.cs");
        var history = NewRaw("hunter2", "Password", file: "src/renamed.cs");

        var checker = new StillPresentChecker(new[] { current });

        checker.IsStillPresent(history).Should().BeTrue();
    }

    [Fact]
    public void Multiple_working_tree_matches_are_indexed()
    {
        var checker = new StillPresentChecker(new[]
        {
            NewRaw("a", "Password"),
            NewRaw("b", "Password"),
            NewRaw("c", "ApiKey"),
        });

        checker.Count.Should().Be(3);
        checker.IsStillPresent(NewRaw("a", "Password")).Should().BeTrue();
        checker.IsStillPresent(NewRaw("b", "Password")).Should().BeTrue();
        checker.IsStillPresent(NewRaw("c", "ApiKey")).Should().BeTrue();
        checker.IsStillPresent(NewRaw("c", "Password")).Should().BeFalse();
    }

    private static RawMatch NewRaw(string value, string secretType, string file = "f.cs") => new()
    {
        PatternId = "test.pattern",
        SecretType = secretType,
        Severity = Severity.Critical,
        SuggestedFix = "fix",
        File = file,
        Line = 1,
        Column = 1,
        Value = value,
        KeyName = null,
    };
}
