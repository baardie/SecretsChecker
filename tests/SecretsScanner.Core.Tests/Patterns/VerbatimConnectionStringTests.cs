using SecretsScanner.Core.Patterns;

namespace SecretsScanner.Core.Tests.Patterns;

/// <summary>
/// Coverage spike for the R3 plan item "multi-line aware match" on C# verbatim connection
/// strings. The existing <c>ConnectionStringSql</c> pattern's value class
/// (<c>[^;""'\r\n]</c>) bans newlines inside the value, but <c>\s*=\s*</c> between key and
/// value already spans newlines — so most real verbatim shapes are caught by the existing
/// pattern. These tests pin that down.
/// </summary>
public sealed class VerbatimConnectionStringTests
{
    private readonly PatternLibrary _library = PatternLibrary.CreateDefault();

    [Fact]
    public void Detects_password_in_csharp_verbatim_string_on_one_logical_line()
    {
        const string code = """
            const string Conn = @"Server=localhost;Password=hunter2-real;";
            """;

        var matches = _library.Scan("Service.cs", code).ToList();

        matches.Should().Contain(m => m.SecretType == "ConnectionString");
    }

    [Fact]
    public void Detects_password_when_csharp_verbatim_string_spans_lines()
    {
        // Whitespace between Password and = and the value spans newlines; the regex's
        // \s*=\s* covers cross-line whitespace and the value itself stays on its line.
        const string code = """
            const string Conn = @"
                Server=localhost;
                Database=app;
                Password=hunter2-real;
                ";
            """;

        var matches = _library.Scan("Service.cs", code).ToList();

        matches.Should().Contain(m => m.SecretType == "ConnectionString");
    }

    [Fact]
    public void Detects_password_when_key_and_equals_are_split_across_lines()
    {
        const string code = """
            const string Conn = @"Server=localhost;Password
                                  =hunter2-real;";
            """;

        var matches = _library.Scan("Service.cs", code).ToList();

        matches.Should().Contain(m => m.SecretType == "ConnectionString");
    }

    [Fact]
    public void Detects_password_inside_csharp_verbatim_json_literal()
    {
        // Nested JSON inside a C# verbatim string: the JSON-key pattern requires literal
        // " characters and won't match (C# escapes them as ""), but the SQL pattern still
        // catches the inner Password= token.
        const string code = @"
            const string Json = @""{ """"ConnectionString"""": """"Server=...;Password=hunter2-real;"""" }"";
            ";

        var matches = _library.Scan("Service.cs", code).ToList();

        matches.Should().Contain(m => m.SecretType == "ConnectionString");
    }
}
