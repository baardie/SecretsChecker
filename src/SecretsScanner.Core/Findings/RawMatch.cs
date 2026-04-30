using System.Security.Cryptography;
using System.Text;

namespace SecretsScanner.Core.Findings;

/// <summary>
/// Internal-only record carrying the captured raw secret value plus its location and pattern
/// metadata. <see cref="Sanitiser"/> is the sole consumer; <see cref="RawMatch"/> never crosses
/// the assembly boundary. Marked <c>internal sealed</c> to enforce this.
/// </summary>
internal sealed record RawMatch
{
    public required string PatternId { get; init; }
    public required string SecretType { get; init; }
    public required Severity Severity { get; init; }
    public required string SuggestedFix { get; init; }

    public required string File { get; init; }
    public required int Line { get; init; }
    public required int Column { get; init; }

    public required string Value { get; init; }
    public string? KeyName { get; init; }

    public FindingSource Source { get; init; } = FindingSource.WorkingTree;

    /// <summary>
    /// Lazily computed 16-byte SHA-256 truncation used by the still-present checker (R4).
    /// Hash bytes never leave the core library; only the resulting boolean does. Marked
    /// <c>internal</c> as belt-and-braces even though the enclosing type is internal —
    /// signals that this is not part of any future "expose RawMatch publicly" reshape.
    /// </summary>
    internal byte[] ValueHash16 => _valueHash16 ??= ComputeHash(Value);

    private byte[]? _valueHash16;

    private static byte[] ComputeHash(string value)
    {
        Span<byte> hash = stackalloc byte[32];
        SHA256.HashData(Encoding.UTF8.GetBytes(value), hash);
        return hash[..16].ToArray();
    }
}
