using SecretsScanner.Core.Configuration;
using SecretsScanner.Core.Walking;

namespace SecretsScanner.Core.Tests.Walking;

public sealed class FileWalkerTests : IDisposable
{
    private readonly string _dir;

    public FileWalkerTests()
    {
        _dir = Path.Combine(Path.GetTempPath(), "secrets-scan-walker-tests-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(_dir);
    }

    public void Dispose()
    {
        try
        {
            if (Directory.Exists(_dir))
            {
                Directory.Delete(_dir, recursive: true);
            }
        }
        catch
        {
            // best effort
        }
    }

    [Fact]
    public void Single_file_path_yields_that_file()
    {
        var path = Path.Combine(_dir, "appsettings.Development.json");
        File.WriteAllText(path, "{}");

        var files = new FileWalker().Walk(path, ScannerOptions.Default).ToList();

        files.Should().ContainSingle();
        files[0].FullPath.Should().Be(path);
        files[0].RelativePath.Should().Be("appsettings.Development.json");
    }

    [Fact]
    public void Single_file_path_to_binary_yields_nothing()
    {
        var path = Path.Combine(_dir, "thing.dll");
        File.WriteAllText(path, "binary content");

        var files = new FileWalker().Walk(path, ScannerOptions.Default).ToList();

        files.Should().BeEmpty();
    }

    [Fact]
    public void Nonexistent_path_yields_nothing()
    {
        var files = new FileWalker().Walk(Path.Combine(_dir, "no-such-thing"), ScannerOptions.Default).ToList();

        files.Should().BeEmpty();
    }
}
