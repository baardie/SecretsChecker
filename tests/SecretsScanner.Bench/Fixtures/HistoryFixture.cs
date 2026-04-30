using LibGit2Sharp;

namespace SecretsScanner.Bench.Fixtures;

/// <summary>
/// Builds a deterministic on-disk git repository with <paramref name="commitCount"/> commits.
/// Every <c>SecretEvery</c>th commit introduces an AWS-shaped secret in a fresh file; the
/// remaining commits modify a rotating set of files with banal content. Average added lines
/// per commit ≈ a single line, which keeps the fixture build fast while still exercising the
/// diff-walker code path.
/// </summary>
internal static class HistoryFixture
{
    private const int FilesInRotation = 10;
    private const int SecretEvery = 100;

    public static void Build(string root, int commitCount)
    {
        Directory.CreateDirectory(root);
        Repository.Init(root);

        using var repo = new Repository(root);
        var baseTime = new DateTimeOffset(2024, 1, 1, 0, 0, 0, TimeSpan.Zero);

        for (var i = 0; i < commitCount; i++)
        {
            var rotated = i % FilesInRotation;
            var relPath = Path.Combine("src", $"file{rotated}.cs");
            var fullPath = Path.Combine(root, relPath);
            Directory.CreateDirectory(Path.GetDirectoryName(fullPath)!);

            File.AppendAllText(fullPath, $"// touch {i}\n");

            if (i % SecretEvery == 0)
            {
                var seedPath = Path.Combine(root, "src", $"leak_{i:D5}.cs");
                var tail = i.ToString("D16").Replace('0', 'A');
                File.WriteAllText(seedPath, $"const string k = \"AKIA{tail}\";\n");
                Commands.Stage(repo, $"src/leak_{i:D5}.cs");
            }

            Commands.Stage(repo, relPath);

            var sig = new Signature("Bench", "bench@example.com", baseTime.AddMinutes(i));
            repo.Commit($"commit {i:D5}", sig, sig);
        }
    }
}
