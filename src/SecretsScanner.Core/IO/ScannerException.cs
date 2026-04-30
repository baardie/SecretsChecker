namespace SecretsScanner.Core.IO;

/// <summary>
/// The single exception type allowed to cross the core library boundary. Carries an opaque
/// error code and an internal file id — never the offending line content, exception message,
/// or stack frame from the underlying failure (R1).
/// </summary>
public sealed class ScannerException : Exception
{
    public ScannerErrorCode Code { get; }
    public int FileId { get; }

    public ScannerException(ScannerErrorCode code, int fileId)
        : base(BuildMessage(code, fileId))
    {
        Code = code;
        FileId = fileId;
    }

    private static string BuildMessage(ScannerErrorCode code, int fileId) =>
        $"scanner error {code} at internal file id {fileId}";
}

public enum ScannerErrorCode
{
    Unknown,
    FileRead,
    EncodingDetection,
    PatternEvaluation,
    Walker,
    Configuration,
    Timeout,
}
