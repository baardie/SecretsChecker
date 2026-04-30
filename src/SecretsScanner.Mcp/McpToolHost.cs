using System.ComponentModel;
using ModelContextProtocol.Server;
using SecretsScanner.Mcp.Tools;

namespace SecretsScanner.Mcp;

/// <summary>
/// MCP transport entry points. Pure adapters: deserialise primitive method parameters into
/// our typed request records, dispatch to the corresponding logic tool, return its
/// already-redacted response. Schema (descriptions, defaults) is driven by the parameter
/// attributes Claude Code consumes.
/// </summary>
[McpServerToolType]
public static class McpToolHost
{
    [McpServerTool(Name = ScanForSecretsTool.ToolName)]
    [Description(
        "Scan a working tree for hardcoded secrets. Reports location only — never values. " +
        "Returns: schemaVersion, truncated, filesSkipped, findings[]. Each finding carries " +
        "file, line, column, secretType, severity, hint (masked field indicator), and " +
        "suggestedFix. PII fields are stripped at the wire boundary.")]
    public static ScanForSecretsResponse ScanForSecrets(
        ScanForSecretsTool tool,
        [Description("Absolute or relative path to a directory or file to scan within the workspace.")]
        string path = "./",
        [Description("Glob patterns to include (e.g. [\"*.cs\", \"appsettings.json\"]). Default: every file.")]
        string[]? include = null,
        [Description("Minimum severity to return: low | medium | high | critical.")]
        string severity = "medium",
        CancellationToken cancellationToken = default)
    {
        var request = new ScanForSecretsRequest
        {
            Path = path,
            Include = include ?? new[] { "*" },
            Severity = severity,
        };
        return tool.Execute(request, cancellationToken);
    }

    [McpServerTool(Name = ScanGitHistoryTool.ToolName)]
    [Description(
        "Scan a git repository's commit history for hardcoded secrets. Reports the earliest " +
        "introduction of each unique secret along with whether it is still present in the " +
        "working tree. Returns: schemaVersion, truncated, commitsWalked, findings[]. " +
        "PII fields are stripped at the wire boundary.")]
    public static ScanGitHistoryResponse ScanGitHistory(
        ScanGitHistoryTool tool,
        [Description("Path to the repository root (must lie inside the workspace).")]
        string path = "./",
        [Description("Branch to scan. Omit to scan all local branches.")]
        string? branch = null,
        [Description("ISO 8601 date — only scan commits at or after this instant.")]
        string? since = null,
        [Description("Maximum number of commits to walk (most-recent first).")]
        int maxCommits = 1000,
        [Description("Minimum severity to return: low | medium | high | critical.")]
        string severity = "medium",
        CancellationToken cancellationToken = default)
    {
        var request = new ScanGitHistoryRequest
        {
            Path = path,
            Branch = branch,
            Since = since,
            MaxCommits = maxCommits,
            Severity = severity,
        };
        return tool.Execute(request, cancellationToken);
    }
}
