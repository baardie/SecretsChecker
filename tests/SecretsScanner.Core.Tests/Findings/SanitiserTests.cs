using SecretsScanner.Core.Findings;

namespace SecretsScanner.Core.Tests.Findings;

public sealed class SanitiserTests
{
    [Fact]
    public void Hint_uses_key_when_present()
    {
        var raw = NewRaw(value: "p@ssw0rd-very-secret", keyName: "Password");

        var finding = Sanitiser.ToWorkingTreeFinding(raw);

        finding.Hint.Should().Be("Password=***");
    }

    [Fact]
    public void Hint_falls_back_to_secret_type_when_no_key()
    {
        var raw = NewRaw(value: "AKIAEXAMPLE0000000000", keyName: null, secretType: "AwsAccessKey");

        var finding = Sanitiser.ToWorkingTreeFinding(raw);

        finding.Hint.Should().Be("AwsAccessKey=***");
    }

    [Fact]
    public void Hint_must_not_contain_value_substring_of_length_4_or_more()
    {
        // Value-bleed simulation: the key contains a 4-char substring of the value.
        var raw = NewRaw(value: "leakyKEY1234567890", keyName: "leakyKEY-name");

        var finding = Sanitiser.ToWorkingTreeFinding(raw);

        finding.Hint.Should().NotContain("leak");
        finding.Hint.Should().NotContain("KEY1");
        finding.Hint.Should().StartWith(raw.SecretType,
            "fail-closed must drop to the static secret-type label (R1)");
    }

    [Fact]
    public void Hint_with_unsafe_key_token_falls_back_to_secret_type()
    {
        var raw = NewRaw(value: "abc", keyName: "weird key with spaces and $$$");

        var finding = Sanitiser.ToWorkingTreeFinding(raw);

        finding.Hint.Should().StartWith(raw.SecretType,
            "key tokens with unsafe characters must drop to the static secret-type label");
    }

    [Fact]
    public void Hint_allows_single_character_overlap_for_normal_field_names()
    {
        // "Password" legitimately contains characters ('a', 's', etc.) that will appear in
        // most high-entropy values. That's expected — only contiguous substring leaks fail.
        var raw = NewRaw(value: "p@ssw0rd-very-secret", keyName: "Password");

        var finding = Sanitiser.ToWorkingTreeFinding(raw);

        finding.Hint.Should().Be("Password=***");
    }

    [Fact]
    public void Entropy_is_rounded_to_one_decimal()
    {
        var raw = NewRaw(value: "abcdefghijklmnop");

        var finding = Sanitiser.ToWorkingTreeFinding(raw);

        // 1 dp rounding caps the precision side-channel.
        var formatted = finding.Entropy.ToString("0.################",
            System.Globalization.CultureInfo.InvariantCulture);
        var decimalPart = formatted.Contains('.') ? formatted.Split('.')[1] : string.Empty;
        decimalPart.Length.Should().BeLessThanOrEqualTo(1);
    }

    [Fact]
    public void Shannon_entropy_low_for_repeated_chars()
    {
        Sanitiser.ShannonEntropy("aaaaaaaa").Should().Be(0d);
    }

    [Fact]
    public void Shannon_entropy_higher_for_mixed_chars()
    {
        Sanitiser.ShannonEntropy("aB3$kP9!xQ2#")
            .Should().BeGreaterThan(3.0);
    }

    private static RawMatch NewRaw(
        string value,
        string? keyName = null,
        string secretType = "Password",
        Severity severity = Severity.High,
        string file = "appsettings.json",
        int line = 1,
        int column = 1) =>
        new()
        {
            PatternId = "test.pattern",
            SecretType = secretType,
            Severity = severity,
            SuggestedFix = "test fix",
            File = file,
            Line = line,
            Column = column,
            Value = value,
            KeyName = keyName,
        };
}
