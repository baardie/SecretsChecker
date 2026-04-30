namespace SecretsScanner.Core.IO;

/// <summary>
/// Wraps every code path that touches potentially-secret-bearing data (regex, AST, file IO,
/// libgit2). Catches all exceptions, drops the original message and stack, and rethrows a
/// <see cref="ScannerException"/> that carries only an opaque code and a file id (R1).
/// </summary>
internal static class SafeBoundary
{
    public static T Run<T>(ScannerErrorCode code, int fileId, Func<T> action)
    {
        try
        {
            return action();
        }
        catch (ScannerException)
        {
            throw;
        }
        catch
        {
            throw new ScannerException(code, fileId);
        }
    }

    public static void Run(ScannerErrorCode code, int fileId, Action action)
    {
        try
        {
            action();
        }
        catch (ScannerException)
        {
            throw;
        }
        catch
        {
            throw new ScannerException(code, fileId);
        }
    }

    /// <summary>
    /// Same as <see cref="Run{T}"/> but returns a default value on failure rather than throwing.
    /// Useful when one bad file should not abort an entire scan.
    /// </summary>
    public static T RunOrDefault<T>(Func<T> action, T fallback)
    {
        try
        {
            return action();
        }
        catch
        {
            return fallback;
        }
    }
}
