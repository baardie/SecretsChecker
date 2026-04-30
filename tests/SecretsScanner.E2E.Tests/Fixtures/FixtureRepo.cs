using LibGit2Sharp;

namespace SecretsScanner.E2E.Tests.Fixtures;

/// <summary>
/// Test helper that builds a real on-disk git repo via LibGit2Sharp. Exposes ergonomic
/// commit / branch / rename / delete operations and cleans up the temp directory on dispose.
/// </summary>
public sealed class FixtureRepo : IDisposable
{
    private static readonly Signature AuthorSignature =
        new("Test Author", "test@example.com", new DateTimeOffset(2024, 3, 15, 10, 0, 0, TimeSpan.Zero));

    public string Path { get; }
    public Repository Repository { get; }

    private int _commitOffset;

    public FixtureRepo()
    {
        Path = System.IO.Path.Combine(System.IO.Path.GetTempPath(), "secrets-scan-fixture-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(Path);
        LibGit2Sharp.Repository.Init(Path);
        Repository = new Repository(Path);
    }

    public void Dispose()
    {
        Repository.Dispose();
        try
        {
            ForceDelete(Path);
        }
        catch
        {
            // best-effort cleanup; the temp folder will get cleaned eventually
        }
    }

    public Commit Commit(string message, params (string Path, string Content)[] files)
    {
        foreach (var (relPath, content) in files)
        {
            var full = System.IO.Path.Combine(Path, relPath);
            Directory.CreateDirectory(System.IO.Path.GetDirectoryName(full)!);
            File.WriteAllText(full, content);
            Commands.Stage(Repository, relPath);
        }

        return CreateCommit(message);
    }

    public Commit DeleteFile(string relPath, string message)
    {
        var full = System.IO.Path.Combine(Path, relPath);
        File.Delete(full);
        Commands.Stage(Repository, relPath);
        return CreateCommit(message);
    }

    public Commit RenameFile(string fromRel, string toRel, string message)
    {
        var fromFull = System.IO.Path.Combine(Path, fromRel);
        var toFull = System.IO.Path.Combine(Path, toRel);
        Directory.CreateDirectory(System.IO.Path.GetDirectoryName(toFull)!);
        File.Move(fromFull, toFull);
        Commands.Stage(Repository, fromRel);
        Commands.Stage(Repository, toRel);
        return CreateCommit(message);
    }

    public Branch CreateBranch(string name, Commit tip) => Repository.CreateBranch(name, tip);

    public void Checkout(string branchName) => Commands.Checkout(Repository, Repository.Branches[branchName]);

    public Tag CreateTag(string name, Commit target) => Repository.ApplyTag(name, target.Sha);

    public Commit CreateOrphanCommit(string message, params (string Path, string Content)[] files)
    {
        // Create a commit with no parents that is not pointed to by any branch — i.e. dangling.
        // Approach: write a tree to the object database, then create a commit referencing it,
        // and DON'T move any ref to point to it.
        var treeDef = new TreeDefinition();
        foreach (var (relPath, content) in files)
        {
            var blob = Repository.ObjectDatabase.CreateBlob(new MemoryStream(System.Text.Encoding.UTF8.GetBytes(content)));
            treeDef.Add(relPath, blob, Mode.NonExecutableFile);
        }
        var tree = Repository.ObjectDatabase.CreateTree(treeDef);
        var sig = SignatureFor(_commitOffset++);
        return Repository.ObjectDatabase.CreateCommit(sig, sig, message, tree, Array.Empty<Commit>(), prettifyMessage: true);
    }

    private Commit CreateCommit(string message)
    {
        var sig = SignatureFor(_commitOffset++);
        return Repository.Commit(message, sig, sig, new CommitOptions { AllowEmptyCommit = true });
    }

    private static Signature SignatureFor(int offset) =>
        new(AuthorSignature.Name, AuthorSignature.Email, AuthorSignature.When.AddMinutes(offset));

    private static void ForceDelete(string path)
    {
        if (!Directory.Exists(path))
        {
            return;
        }

        // libgit2 leaves some files with read-only attribute on Windows.
        foreach (var file in Directory.EnumerateFiles(path, "*", SearchOption.AllDirectories))
        {
            try { File.SetAttributes(file, FileAttributes.Normal); } catch { /* ignore */ }
        }

        Directory.Delete(path, recursive: true);
    }
}
