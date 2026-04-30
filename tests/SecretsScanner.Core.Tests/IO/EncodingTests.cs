using System.Text;
using SecretsScanner.Core;

namespace SecretsScanner.Core.Tests.IO;

/// <summary>
/// R9: encoding detection must handle the common cases that bite real .NET projects —
/// UTF-8, UTF-8 with BOM, UTF-16 LE with BOM (which Visual Studio sometimes saves
/// <c>appsettings.json</c> as).
/// </summary>
public sealed class EncodingTests : IDisposable
{
    private readonly string _root;

    public EncodingTests()
    {
        _root = Path.Combine(Path.GetTempPath(), $"secretsscan-enc-{Guid.NewGuid():N}");
        Directory.CreateDirectory(_root);
    }

    [Theory]
    [MemberData(nameof(EncodingCases))]
    public void Detects_seeded_secret_regardless_of_encoding(string label, Encoding encoding)
    {
        _ = label;
        var file = Path.Combine(_root, "appsettings.json");
        var text =
            "{\n  \"ConnectionStrings\": { \"Default\": \"Server=db;User=sa;Password=Pa$$w0rd!\" }\n}";
        File.WriteAllBytes(file, encoding.GetPreamble().Concat(encoding.GetBytes(text)).ToArray());

        var scanner = new Scanner();
        var result = scanner.Scan(_root);

        result.Findings.Should().Contain(f => f.SecretType == "ConnectionString",
            $"encoding {label} must not defeat detection");
    }

    public static IEnumerable<object[]> EncodingCases()
    {
        yield return new object[] { "utf-8", new UTF8Encoding(encoderShouldEmitUTF8Identifier: false) };
        yield return new object[] { "utf-8-bom", new UTF8Encoding(encoderShouldEmitUTF8Identifier: true) };
        yield return new object[] { "utf-16-le-bom", Encoding.Unicode };
    }

    public void Dispose()
    {
        try
        {
            Directory.Delete(_root, recursive: true);
        }
        catch
        {
            // best effort
        }
    }
}
