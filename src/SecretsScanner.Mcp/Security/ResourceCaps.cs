namespace SecretsScanner.Mcp.Security;

/// <summary>
/// R5 — per-invocation budget for the MCP server. Defaults: 100 000 files and a 60-second
/// wall-clock budget. Exceeding either returns a partial result with <c>truncated: true</c>
/// rather than failing outright.
///
/// Wall-clock enforcement uses a <see cref="CancellationTokenSource"/> the caller links
/// against the scanner; the scanner checks the token at file/commit boundaries and bails.
/// File-count enforcement is propagated through <see cref="Core.Configuration.ScannerOptions.MaxFiles"/>.
/// A byte-count cap is intentionally absent in v1: bounding files + wall-clock + per-file size
/// already shapes the worst case; a separate bytes-read counter would just duplicate that.
/// </summary>
public sealed record ResourceCaps
{
    public int MaxFiles { get; init; } = 100_000;
    public TimeSpan MaxWallClock { get; init; } = TimeSpan.FromSeconds(60);

    public static ResourceCaps Default { get; } = new();

    /// <summary>
    /// Creates a cancellation source that fires after <see cref="MaxWallClock"/> and is also
    /// linked to the caller's outer token.
    /// </summary>
    public CancellationTokenSource CreateLinkedSource(CancellationToken outer = default)
    {
        var cts = CancellationTokenSource.CreateLinkedTokenSource(outer);
        cts.CancelAfter(MaxWallClock);
        return cts;
    }
}
