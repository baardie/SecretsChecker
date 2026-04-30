using LibGit2Sharp;
using SecretsScanner.Core.Configuration;
using SecretsScanner.Core.Findings;
using SecretsScanner.Core.IO;
using SecretsScanner.Core.Patterns;
using SecretsScanner.Core.Walking;

namespace SecretsScanner.Core;

/// <summary>
/// Orchestrator for git-history scans. Wires <see cref="GitHistoryWalker"/> +
/// <see cref="PatternLibrary"/> + <see cref="Sanitiser"/> + <see cref="StillPresentChecker"/>,
/// dedups by <c>(SecretType, ValueHash16)</c> keeping the earliest commit (Q6 + plan dedup
/// rule), and returns sanitised <see cref="HistoryFinding"/> / <see cref="CommitMessageFinding"/>
/// objects. Raw values never leave this method.
/// </summary>
public sealed class HistoryScanner
{
    private readonly PatternLibrary _patterns;

    public HistoryScanner(PatternLibrary? patterns = null)
    {
        _patterns = patterns ?? PatternLibrary.CreateDefault();
    }

    /// <summary>
    /// Counts commits the walker would visit for the cap policy (Q8). Public so the CLI can
    /// enforce <c>--all-history</c> without opening the repo a second time.
    /// </summary>
    public int CountReachableCommits(string repoPath, GitHistoryOptions historyOptions)
    {
        using var walker = new GitHistoryWalker(repoPath);
        return walker.CountReachableCommits(historyOptions);
    }

    public HistoryScanResult Scan(
        string repoPath,
        GitHistoryOptions historyOptions,
        ScannerOptions? scannerOptions = null,
        CancellationToken cancellationToken = default)
    {
        scannerOptions ??= ScannerOptions.Default;

        // Defer the working-tree rescan until we know we have a HistoryFinding to compute
        // stillPresent for. CommitMessageFinding-only scans avoid the rescan entirely.
        var capturedOptions = scannerOptions;
        var stillPresent = new Lazy<StillPresentChecker>(
            () => BuildStillPresentChecker(repoPath, capturedOptions, cancellationToken),
            LazyThreadSafetyMode.None);

        var byKey = new Dictionary<string, Candidate>(StringComparer.Ordinal);
        var commitsWalked = 0;
        var truncated = false;

        using var walker = new GitHistoryWalker(repoPath);
        foreach (var commit in walker.EnumerateCommitDiffs(historyOptions))
        {
            if (cancellationToken.IsCancellationRequested)
            {
                truncated = true;
                break;
            }

            commitsWalked++;
            ScanFiles(commit, scannerOptions, byKey);

            if (historyOptions.ScanCommitMessages && !string.IsNullOrEmpty(commit.Message))
            {
                ScanCommitMessage(commit, scannerOptions, byKey);
            }
        }

        var findings = new List<Finding>(byKey.Count);
        foreach (var candidate in byKey.Values)
        {
            findings.Add(Materialise(candidate, stillPresent, scannerOptions.RedactPii));
        }

        return new HistoryScanResult(findings, commitsWalked, truncated);
    }

    private void ScanFiles(CommitDiff commit, ScannerOptions options, Dictionary<string, Candidate> byKey)
    {
        foreach (var file in commit.Files)
        {
            foreach (var raw in _patterns.Scan(file.Path, file.PostCommitContent))
            {
                if (!file.AddedLineNumbers.Contains(raw.Line))
                {
                    continue;
                }
                if (!raw.Severity.MeetsMinimum(options.MinimumSeverity))
                {
                    continue;
                }

                Add(byKey, FindingSource.History, raw, commit);
            }
        }
    }

    private void ScanCommitMessage(CommitDiff commit, ScannerOptions options, Dictionary<string, Candidate> byKey)
    {
        foreach (var raw in _patterns.ScanAllPatterns("<commit-message>", commit.Message))
        {
            if (!raw.Severity.MeetsMinimum(options.MinimumSeverity))
            {
                continue;
            }

            Add(byKey, FindingSource.CommitMessage, raw, commit);
        }
    }

    private static void Add(
        Dictionary<string, Candidate> byKey,
        FindingSource source,
        RawMatch raw,
        CommitDiff commit)
    {
        var key = string.Concat(
            source == FindingSource.CommitMessage ? "msg:" : "file:",
            raw.SecretType, ":",
            Convert.ToHexString(raw.ValueHash16));

        if (byKey.TryGetValue(key, out var existing))
        {
            if (commit.CommitDate < existing.Commit.CommitDate)
            {
                byKey[key] = new Candidate(source, raw, commit);
            }
        }
        else
        {
            byKey[key] = new Candidate(source, raw, commit);
        }
    }

    private static Finding Materialise(Candidate candidate, Lazy<StillPresentChecker> stillPresent, bool redactPii)
    {
        // stillPresent is only forced for true history findings; commit-message findings
        // don't carry the flag.
        Finding finding = candidate.Source == FindingSource.CommitMessage
            ? Sanitiser.ToCommitMessageFinding(
                candidate.Raw,
                candidate.Commit.CommitSha,
                candidate.Commit.CommitDate,
                candidate.Commit.AuthorName)
            : Sanitiser.ToHistoryFinding(
                candidate.Raw,
                candidate.Commit.CommitSha,
                candidate.Commit.CommitDate,
                candidate.Commit.AuthorName,
                candidate.Commit.Branches,
                stillPresent.Value.IsStillPresent(candidate.Raw));

        return Redaction.Apply(finding, redactPii);
    }

    private StillPresentChecker BuildStillPresentChecker(string repoPath, ScannerOptions scannerOptions, CancellationToken cancellationToken)
    {
        // The still-present check needs (SecretType, ValueHash16) for every raw match in the
        // current working tree. We derive the working-tree directory from the libgit2 repo
        // discovery (handles bare-vs-worktree-vs-subdir transparently); on failure we degrade
        // to the empty checker so a missing working tree still produces a usable history scan.
        // libgit2 calls go through SafeBoundary so any thrown message can't escape (R1).
        var workingDir = SafeBoundary.RunOrDefault<string?>(() =>
        {
            using var repo = new Repository(repoPath);
            return repo.Info.WorkingDirectory;
        }, null);

        if (string.IsNullOrEmpty(workingDir) || !Directory.Exists(workingDir))
        {
            return StillPresentChecker.Empty;
        }

        var rawMatches = new Scanner(_patterns).EnumerateRawMatches(workingDir, scannerOptions, cancellationToken);
        return new StillPresentChecker(rawMatches);
    }

    private readonly record struct Candidate(FindingSource Source, RawMatch Raw, CommitDiff Commit);
}

public sealed record HistoryScanResult(IReadOnlyList<Finding> Findings, int CommitsWalked, bool Truncated = false);
