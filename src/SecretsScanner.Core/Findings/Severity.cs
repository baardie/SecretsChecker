namespace SecretsScanner.Core.Findings;

public enum Severity
{
    Low,
    Medium,
    High,
    Critical,
}

public static class SeverityExtensions
{
    public static string ToWireString(this Severity severity) => severity switch
    {
        Severity.Low => "low",
        Severity.Medium => "medium",
        Severity.High => "high",
        Severity.Critical => "critical",
        _ => throw new ArgumentOutOfRangeException(nameof(severity)),
    };

    public static bool MeetsMinimum(this Severity severity, Severity minimum) =>
        (int)severity >= (int)minimum;
}
