using SecretsScanner.Core.Configuration;
using SecretsScanner.Core.Findings;
using SecretsScanner.Core.IO;
using SecretsScanner.Core.Patterns;
using SecretsScanner.Core.Walking;

namespace SecretsScanner.Core;

/// <summary>
/// Orchestrator that ties the file walker, encoding detector, binary filter, pattern library,
/// and sanitiser into a single entry point. Returns sanitised <see cref="Finding"/> objects;
/// raw values never leave this method.
/// </summary>
public sealed class Scanner
{
    private readonly PatternLibrary _patterns;
    private readonly FileWalker _walker;

    public Scanner(PatternLibrary? patterns = null, FileWalker? walker = null)
    {
        _patterns = patterns ?? PatternLibrary.CreateDefault();
        _walker = walker ?? new FileWalker();
    }

    public ScanResult Scan(string rootPath, ScannerOptions? options = null, CancellationToken cancellationToken = default)
    {
        options ??= ScannerOptions.Default;

        var findings = new List<Finding>();
        var skipped = 0;
        var truncated = false;

        foreach (var raw in EnumerateRawMatches(rootPath, options, cancellationToken, ref skipped, ref truncated))
        {
            if (!raw.Severity.MeetsMinimum(options.MinimumSeverity))
            {
                continue;
            }

            var finding = Sanitiser.ToWorkingTreeFinding(raw);
            findings.Add(Redaction.Apply(finding, options.RedactPii));
        }

        return new ScanResult(findings, skipped, truncated);
    }

    /// <summary>
    /// Yields raw matches without sanitising — for internal consumers that need access to
    /// <c>ValueHash16</c> for the still-present check (R4). Never crosses the public boundary;
    /// callers in this assembly must turn results into <see cref="Finding"/>s before exposing.
    /// </summary>
    internal IEnumerable<RawMatch> EnumerateRawMatches(string rootPath, ScannerOptions options, CancellationToken cancellationToken = default)
    {
        var skipped = 0;
        var truncated = false;
        return EnumerateRawMatches(rootPath, options, cancellationToken, ref skipped, ref truncated);
    }

    private IEnumerable<RawMatch> EnumerateRawMatches(
        string rootPath,
        ScannerOptions options,
        CancellationToken cancellationToken,
        ref int skipped,
        ref bool truncated)
    {
        var rawMatches = new List<RawMatch>();
        var fileId = 0;
        foreach (var file in _walker.Walk(rootPath, options))
        {
            if (cancellationToken.IsCancellationRequested)
            {
                truncated = true;
                break;
            }

            if (options.MaxFiles is { } cap && fileId >= cap)
            {
                truncated = true;
                break;
            }

            fileId++;

            var content = SafeBoundary.RunOrDefault(() => ReadTextOrNull(file.FullPath), null);
            if (content is null)
            {
                skipped++;
                continue;
            }

            foreach (var raw in _patterns.Scan(file.RelativePath, content))
            {
                rawMatches.Add(raw);
            }
        }

        return rawMatches;
    }

    /// <summary>
    /// Returns the file's text content, or <c>null</c> if the file is binary or any IO/
    /// encoding step failed. Null is the correct sentinel for "skip this file"; the caller
    /// in <see cref="EnumerateRawMatches"/> increments <c>skipped</c> on null.
    /// </summary>
    private static string? ReadTextOrNull(string fullPath)
    {
        using var stream = File.OpenRead(fullPath);
        if (BinaryFileFilter.LooksBinary(stream))
        {
            return null;
        }

        return EncodingDetector.ReadAllText(stream);
    }
}

public sealed record ScanResult(IReadOnlyList<Finding> Findings, int FilesSkipped, bool Truncated = false);
