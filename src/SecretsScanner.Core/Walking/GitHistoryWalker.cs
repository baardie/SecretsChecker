using LibGit2Sharp;
using SecretsScanner.Core.Configuration;
using SecretsScanner.Core.IO;

namespace SecretsScanner.Core.Walking;

/// <summary>
/// Walks the commit graph of a libgit2 repository and emits <see cref="CommitDiff"/>s
/// suitable for pattern application. Single-repo, single-threaded; the parallel processor
/// (R6) wraps this with channels and per-worker repositories.
///
/// Coverage rules (R7):
///   • Renames detected via <see cref="SimilarityOptions.Default"/> — a rename is one change.
///   • Tags walked by default; opt out via <see cref="GitHistoryOptions.IncludeTags"/>.
///   • Dangling commits opt-in via <see cref="GitHistoryOptions.IncludeUnreachable"/>.
///   • Reflog entries opt-in via <see cref="GitHistoryOptions.IncludeReflog"/>.
///   • Parent-less first commit diffed against the empty tree.
/// </summary>
internal sealed class GitHistoryWalker : IDisposable
{
    private readonly Repository _repo;

    public GitHistoryWalker(string repoPath)
    {
        _repo = new Repository(repoPath);
    }

    public void Dispose() => _repo.Dispose();

    /// <summary>
    /// Counts the commits the walker would visit at <see cref="GitHistoryOptions.MaxCommits"/>
    /// = null. Used by the commit-cap policy (Q8) to decide whether to warn-and-require
    /// <c>--all-history</c>.
    /// </summary>
    public int CountReachableCommits(GitHistoryOptions options)
    {
        var seen = new HashSet<LibGit2Sharp.ObjectId>();

        foreach (var tip in EnumerateTipCommits(options))
        {
            var filter = new CommitFilter { IncludeReachableFrom = tip };
            foreach (var c in _repo.Commits.QueryBy(filter))
            {
                if (options.Since is { } since && c.Author.When < since)
                {
                    continue;
                }
                seen.Add(c.Id);
            }
        }

        if (options.IncludeUnreachable)
        {
            foreach (var c in EnumerateUnreachableCommits(seen))
            {
                if (options.Since is { } since && c.Author.When < since)
                {
                    continue;
                }
                seen.Add(c.Id);
            }
        }

        return seen.Count;
    }

    public IEnumerable<CommitDiff> EnumerateCommitDiffs(GitHistoryOptions options)
    {
        var branchMembership = ComputeBranchMembership(options);
        var capped = SelectCappedCommits(options);

        foreach (var commit in capped)
        {
            var branches = branchMembership.TryGetValue(commit.Id, out var set)
                ? (IReadOnlyList<string>)set.OrderBy(s => s, StringComparer.Ordinal).ToList()
                : Array.Empty<string>();

            var files = SafeBoundary.RunOrDefault(() => ComputeFileDiffs(commit), Array.Empty<FileDiff>())!;

            yield return new CommitDiff(
                CommitSha: commit.Sha,
                CommitDate: commit.Author.When,
                AuthorName: commit.Author.Name ?? "(unknown)",
                Message: commit.Message ?? string.Empty,
                Branches: branches,
                Files: files);
        }
    }

    /// <summary>
    /// Selects commits in scope, capped to <see cref="GitHistoryOptions.MaxCommits"/> via a
    /// bounded min-heap keyed by author time. For a 100 000-commit repo with
    /// <c>MaxCommits = 1 000</c>, we hold at most 1 000 entries in memory rather than
    /// materialising the whole reachable graph and then sorting it.
    /// </summary>
    private List<Commit> SelectCappedCommits(GitHistoryOptions options)
    {
        var seen = new HashSet<ObjectId>();
        var heap = options.MaxCommits is { } cap ? new PriorityQueue<Commit, long>(cap) : null;
        var unbounded = options.MaxCommits is null ? new List<Commit>() : null;

        void Consider(Commit commit)
        {
            if (!seen.Add(commit.Id))
            {
                return;
            }
            if (options.Since is { } since && commit.Author.When < since)
            {
                return;
            }

            if (heap is not null)
            {
                var when = commit.Author.When.UtcTicks;
                if (heap.Count < options.MaxCommits!.Value)
                {
                    heap.Enqueue(commit, when);
                }
                else if (heap.TryPeek(out _, out var oldestWhen) && when > oldestWhen)
                {
                    heap.DequeueEnqueue(commit, when);
                }
            }
            else
            {
                unbounded!.Add(commit);
            }
        }

        foreach (var tip in EnumerateTipCommits(options))
        {
            var filter = new CommitFilter
            {
                IncludeReachableFrom = tip,
                SortBy = CommitSortStrategies.Topological | CommitSortStrategies.Time,
            };
            foreach (var commit in _repo.Commits.QueryBy(filter))
            {
                Consider(commit);
            }
        }

        if (options.IncludeUnreachable)
        {
            foreach (var commit in EnumerateUnreachableCommits(seen))
            {
                Consider(commit);
            }
        }

        var collected = heap is not null
            ? DrainHeap(heap)
            : unbounded!;
        collected.Sort((a, b) => b.Author.When.CompareTo(a.Author.When));
        return collected;
    }

    private static List<Commit> DrainHeap(PriorityQueue<Commit, long> heap)
    {
        var result = new List<Commit>(heap.Count);
        while (heap.TryDequeue(out var c, out _))
        {
            result.Add(c);
        }
        return result;
    }

    private IEnumerable<Commit> EnumerateTipCommits(GitHistoryOptions options)
    {
        if (options.Branch is { } branchName)
        {
            var branch = _repo.Branches[branchName];
            if (branch is not null)
            {
                yield return branch.Tip;
            }
            yield break;
        }

        foreach (var branch in _repo.Branches.Where(b => !b.IsRemote))
        {
            if (branch.Tip is not null)
            {
                yield return branch.Tip;
            }
        }

        if (options.IncludeTags)
        {
            foreach (var tag in _repo.Tags)
            {
                if (tag.PeeledTarget is Commit c)
                {
                    yield return c;
                }
            }
        }
    }

    private IReadOnlyDictionary<ObjectId, HashSet<string>> ComputeBranchMembership(GitHistoryOptions options)
    {
        var map = new Dictionary<ObjectId, HashSet<string>>();

        IEnumerable<(string Label, Commit Tip)> tips = options.Branch is { } singleBranch
            ? _repo.Branches[singleBranch] is { } b ? new[] { (b.FriendlyName, b.Tip) } : Array.Empty<(string, Commit)>()
            : _repo.Branches
                .Where(branch => !branch.IsRemote && branch.Tip is not null)
                .Select(branch => (branch.FriendlyName, branch.Tip));

        foreach (var (label, tip) in tips)
        {
            var filter = new CommitFilter { IncludeReachableFrom = tip };
            foreach (var c in _repo.Commits.QueryBy(filter))
            {
                if (!map.TryGetValue(c.Id, out var set))
                {
                    set = new HashSet<string>(StringComparer.Ordinal);
                    map[c.Id] = set;
                }
                set.Add(label);
            }
        }

        return map;
    }

    private IEnumerable<Commit> EnumerateUnreachableCommits(HashSet<ObjectId> alreadySeen)
    {
        // libgit2's CommitsForRepoLayout yields every commit in the object database. Filtering
        // by "not in alreadySeen" gives us the unreachable / dangling set.
        foreach (var sha in _repo.ObjectDatabase.OfType<Commit>())
        {
            if (!alreadySeen.Contains(sha.Id))
            {
                yield return sha;
            }
        }
    }

    private IReadOnlyList<FileDiff> ComputeFileDiffs(Commit commit)
    {
        var parentTree = commit.Parents.FirstOrDefault()?.Tree;
        var compareOptions = new CompareOptions
        {
            Similarity = SimilarityOptions.Default,
            IncludeUnmodified = false,
        };

        var patch = _repo.Diff.Compare<Patch>(parentTree, commit.Tree, compareOptions);

        var files = new List<FileDiff>();
        foreach (var entry in patch)
        {
            if (entry.Status == ChangeKind.Deleted)
            {
                continue;
            }

            var addedLines = UnifiedDiffParser
                .EnumerateAddedLines(entry.Patch)
                .Select(l => l.NewLineNumber)
                .ToHashSet();

            if (addedLines.Count == 0)
            {
                continue;
            }

            // Route every libgit2-touching call through SafeBoundary so any thrown exception
            // has its message and stack scrubbed before it can leak (R1).
            var content = SafeBoundary.RunOrDefault(() =>
            {
                var blob = _repo.Lookup<Blob>(entry.Oid);
                return blob is null || blob.IsBinary ? string.Empty : blob.GetContentText();
            }, string.Empty)!;

            if (string.IsNullOrEmpty(content))
            {
                continue;
            }

            files.Add(new FileDiff(entry.Path, content, addedLines));
        }

        return files;
    }
}
