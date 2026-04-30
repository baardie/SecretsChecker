using System.Text;

namespace SecretsScanner.Bench.Fixtures;

/// <summary>
/// Builds a deterministic on-disk working-tree of <paramref name="fileCount"/> C# files. One
/// in every <c>SecretEvery</c> files contains a syntactically valid AWS access key so the
/// pattern library has real work to do; the rest are clean. File contents are stable so a
/// re-run produces identical bytes.
/// </summary>
internal static class WorkingTreeFixture
{
    private const int LinesPerFile = 100;
    private const int SecretEvery = 50;

    public static void Build(string root, int fileCount)
    {
        Directory.CreateDirectory(root);

        for (var i = 0; i < fileCount; i++)
        {
            var modDir = Path.Combine(root, "src", $"Mod{i / 25}");
            Directory.CreateDirectory(modDir);

            var path = Path.Combine(modDir, $"File{i:D5}.cs");
            File.WriteAllText(path, BuildFileContent(i));
        }
    }

    private static string BuildFileContent(int seed)
    {
        var sb = new StringBuilder(LinesPerFile * 64);
        sb.AppendLine("using System;");
        sb.AppendLine($"namespace SecretsBench.Mod{seed / 25};");
        sb.AppendLine();
        sb.AppendLine($"public sealed class Service{seed:D5}");
        sb.AppendLine("{");

        for (var i = 0; i < LinesPerFile - 8; i++)
        {
            sb.AppendLine($"    public string Method{i:D3}(string input) => input + \"_v{i}\";");
        }

        if (seed % SecretEvery == 0)
        {
            // 4 + 16 alphanumeric chars; valid AKIA shape, deterministic bytes.
            var tail = seed.ToString("D16").Replace('0', 'A');
            sb.AppendLine($"    private const string AwsKey = \"AKIA{tail}\";");
        }

        sb.AppendLine("}");
        return sb.ToString();
    }
}
