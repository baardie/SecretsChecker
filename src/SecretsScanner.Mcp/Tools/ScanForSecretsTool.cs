using SecretsScanner.Core;
using SecretsScanner.Core.Configuration;
using SecretsScanner.Core.Findings;
using SecretsScanner.Mcp.Output;
using SecretsScanner.Mcp.Security;
using Redaction = SecretsScanner.Core.Findings.Redaction;

namespace SecretsScanner.Mcp.Tools;

/// <summary>
/// MCP tool: <c>scan_for_secrets</c>. Pure C# logic — the transport in <c>Program.cs</c>
/// just deserialises the request and serialises the response.
///
/// Invariants enforced here regardless of caller:
///   • Path is canonicalised and bound to the workspace (R5).
///   • PII redaction is forced on (R8); entropy is dropped at the wire boundary (R1).
///   • Wall-clock cap fires through a linked <see cref="CancellationTokenSource"/>; on
///     trip the result is partial with <c>truncated: true</c> rather than an error.
/// </summary>
public sealed class ScanForSecretsTool
{
    public const string ToolName = "scan_for_secrets";

    private readonly WorkspaceBoundary _boundary;
    private readonly ResourceCaps _caps;
    private readonly Func<Scanner> _scannerFactory;

    public ScanForSecretsTool(WorkspaceBoundary boundary, ResourceCaps caps, Func<Scanner>? scannerFactory = null)
    {
        _boundary = boundary;
        _caps = caps;
        _scannerFactory = scannerFactory ?? (() => new Scanner());
    }

    public ScanForSecretsResponse Execute(ScanForSecretsRequest request, CancellationToken outer = default)
    {
        if (!TryParseSeverity(request.Severity, out var minimum))
        {
            return ScanForSecretsResponse.Failure($"invalid severity: '{request.Severity}'. Allowed: low, medium, high, critical");
        }

        var decision = _boundary.Validate(request.Path);
        if (!decision.Allowed)
        {
            return ScanForSecretsResponse.Failure(decision.Reason ?? "path rejected");
        }

        using var cts = _caps.CreateLinkedSource(outer);

        var scannerOptions = new ScannerOptions
        {
            MinimumSeverity = minimum,
            RedactPii = true,
            MaxFiles = _caps.MaxFiles,
            IncludeGlobs = request.Include is { Length: > 0 } && !IsDefaultGlob(request.Include)
                ? request.Include
                : Array.Empty<string>(),
        };

        ScanResult result;
        try
        {
            result = _scannerFactory().Scan(decision.CanonicalPath, scannerOptions, cts.Token);
        }
        catch (DirectoryNotFoundException)
        {
            return ScanForSecretsResponse.Failure($"path not found: {Redaction.RedactHomePath(decision.CanonicalPath)}");
        }

        return new ScanForSecretsResponse
        {
            Truncated = result.Truncated,
            TruncatedReason = result.Truncated ? "wall-clock or budget cap exceeded" : null,
            FilesSkipped = result.FilesSkipped,
            Findings = McpFindingMapper.MapAll(result.Findings),
        };
    }

    private static bool TryParseSeverity(string raw, out Severity severity)
        => Enum.TryParse(raw, ignoreCase: true, out severity);

    private static bool IsDefaultGlob(IReadOnlyList<string> include)
        => include.Count == 1 && (include[0] == "*" || include[0] == "**" || include[0] == "**/*");
}

public sealed record ScanForSecretsRequest
{
    public string Path { get; init; } = "./";
    public string[] Include { get; init; } = new[] { "*" };
    public string Severity { get; init; } = "medium";
}

public sealed record ScanForSecretsResponse
{
    public string SchemaVersion { get; init; } = "1";
    public bool Truncated { get; init; }
    public string? TruncatedReason { get; init; }
    public int FilesSkipped { get; init; }
    public IReadOnlyList<object> Findings { get; init; } = Array.Empty<object>();
    public string? Error { get; init; }

    public static ScanForSecretsResponse Failure(string error) => new() { Error = error };
}
