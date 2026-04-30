using LibGit2Sharp;
using SecretsScanner.Core;
using SecretsScanner.Core.Configuration;
using SecretsScanner.Core.Findings;
using SecretsScanner.Mcp.Output;
using SecretsScanner.Mcp.Security;
using Redaction = SecretsScanner.Core.Findings.Redaction;

namespace SecretsScanner.Mcp.Tools;

/// <summary>
/// MCP tool: <c>scan_git_history</c>. Mirrors <see cref="ScanForSecretsTool"/> but for the
/// commit-history scanner. Same R5 path bounds, R8 forced redaction, R1 entropy strip.
/// </summary>
public sealed class ScanGitHistoryTool
{
    public const string ToolName = "scan_git_history";

    private readonly WorkspaceBoundary _boundary;
    private readonly ResourceCaps _caps;
    private readonly Func<HistoryScanner> _scannerFactory;

    public ScanGitHistoryTool(WorkspaceBoundary boundary, ResourceCaps caps, Func<HistoryScanner>? scannerFactory = null)
    {
        _boundary = boundary;
        _caps = caps;
        _scannerFactory = scannerFactory ?? (() => new HistoryScanner());
    }

    public ScanGitHistoryResponse Execute(ScanGitHistoryRequest request, CancellationToken outer = default)
    {
        if (!TryParseSeverity(request.Severity, out var minimum))
        {
            return ScanGitHistoryResponse.Failure($"invalid severity: '{request.Severity}'. Allowed: low, medium, high, critical");
        }

        DateTimeOffset? since = null;
        if (!string.IsNullOrWhiteSpace(request.Since))
        {
            if (!DateTimeOffset.TryParse(request.Since, out var parsed))
            {
                return ScanGitHistoryResponse.Failure($"invalid since: '{request.Since}' (expected ISO-8601)");
            }
            since = parsed;
        }

        if (request.MaxCommits <= 0)
        {
            return ScanGitHistoryResponse.Failure($"maxCommits must be positive (got {request.MaxCommits})");
        }

        var decision = _boundary.Validate(request.Path);
        if (!decision.Allowed)
        {
            return ScanGitHistoryResponse.Failure(decision.Reason ?? "path rejected");
        }

        using var cts = _caps.CreateLinkedSource(outer);

        var historyOptions = new GitHistoryOptions
        {
            Branch = string.IsNullOrWhiteSpace(request.Branch) ? null : request.Branch,
            Since = since,
            MaxCommits = request.MaxCommits,
        };

        var scannerOptions = new ScannerOptions
        {
            MinimumSeverity = minimum,
            RedactPii = true,
            MaxFiles = _caps.MaxFiles,
        };

        HistoryScanResult result;
        try
        {
            result = _scannerFactory().Scan(decision.CanonicalPath, historyOptions, scannerOptions, cts.Token);
        }
        catch (RepositoryNotFoundException)
        {
            return ScanGitHistoryResponse.Failure($"not a git repository: {Redaction.RedactHomePath(decision.CanonicalPath)}");
        }
        catch (DirectoryNotFoundException)
        {
            return ScanGitHistoryResponse.Failure($"path not found: {Redaction.RedactHomePath(decision.CanonicalPath)}");
        }

        return new ScanGitHistoryResponse
        {
            Truncated = result.Truncated,
            TruncatedReason = result.Truncated ? "wall-clock or budget cap exceeded" : null,
            CommitsWalked = result.CommitsWalked,
            Findings = McpFindingMapper.MapAll(result.Findings),
        };
    }

    private static bool TryParseSeverity(string raw, out Severity severity)
        => Enum.TryParse(raw, ignoreCase: true, out severity);
}

public sealed record ScanGitHistoryRequest
{
    public string Path { get; init; } = "./";
    public string? Branch { get; init; }
    public string? Since { get; init; }
    public int MaxCommits { get; init; } = 1000;
    public string Severity { get; init; } = "medium";
}

public sealed record ScanGitHistoryResponse
{
    public string SchemaVersion { get; init; } = "1";
    public bool Truncated { get; init; }
    public string? TruncatedReason { get; init; }
    public int CommitsWalked { get; init; }
    public IReadOnlyList<object> Findings { get; init; } = Array.Empty<object>();
    public string? Error { get; init; }

    public static ScanGitHistoryResponse Failure(string error) => new() { Error = error };
}
