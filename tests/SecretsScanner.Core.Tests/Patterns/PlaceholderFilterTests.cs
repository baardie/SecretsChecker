using SecretsScanner.Core.Patterns;

namespace SecretsScanner.Core.Tests.Patterns;

public sealed class PlaceholderFilterTests
{
    [Theory]
    [InlineData("changeme")]
    [InlineData("ChangeMe")]
    [InlineData("your-secret-here")]
    [InlineData("placeholder")]
    [InlineData("***")]
    [InlineData("xxxx")]
    [InlineData("XXXXX")]
    [InlineData("")]
    [InlineData("   ")]
    [InlineData("<secret>")]
    [InlineData("dummy")]
    [InlineData("\"placeholder\"")]
    public void Common_placeholder_strings_are_filtered(string value)
    {
        PlaceholderFilter.IsPlaceholder(value).Should().BeTrue();
    }

    [Theory]
    [InlineData("p@ssw0rd!real")]
    [InlineData("AKIAEXAMPLE1234567")]
    [InlineData("real-looking-key-123")]
    public void Real_looking_strings_are_not_filtered(string value)
    {
        PlaceholderFilter.IsPlaceholder(value).Should().BeFalse();
    }
}
