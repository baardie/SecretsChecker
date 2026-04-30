using System.Collections.Frozen;

namespace SecretsScanner.Core.IO;

/// <summary>
/// Two-stage binary detection (R9):
///   1. Fast extension denylist for obvious binary types.
///   2. NUL-byte sniff over the first 8 KiB of the file.
/// </summary>
public static class BinaryFileFilter
{
    private const int SniffBytes = 8192;

    private static readonly FrozenSet<string> BinaryExtensions =
        new[]
        {
            ".dll", ".exe", ".pdb", ".so", ".dylib",
            ".png", ".jpg", ".jpeg", ".gif", ".bmp", ".ico", ".webp",
            ".pfx", ".snk", ".p12", ".cer", ".crt", ".der",
            ".zip", ".7z", ".tar", ".gz", ".bz2", ".xz",
            ".nupkg", ".wasm", ".woff", ".woff2", ".ttf", ".otf",
            ".pdf", ".mp3", ".mp4", ".mov", ".avi",
        }.ToFrozenSet(StringComparer.OrdinalIgnoreCase);

    public static bool IsBinaryByExtension(string path)
    {
        var ext = Path.GetExtension(path);
        return !string.IsNullOrEmpty(ext) && BinaryExtensions.Contains(ext);
    }

    /// <summary>
    /// Reads up to <see cref="SniffBytes"/> from the stream and decides whether the content
    /// looks binary. Detects common UTF-16 / UTF-32 BOMs first and treats those as text even
    /// though their ASCII content contains NUL high-bytes. For everything else, a NUL byte in
    /// the sniff window means binary. Always rewinds the stream before returning.
    /// </summary>
    public static bool LooksBinary(Stream stream)
    {
        var origin = stream.CanSeek ? stream.Position : 0L;
        try
        {
            Span<byte> buffer = stackalloc byte[SniffBytes];
            var read = stream.Read(buffer);
            if (read == 0)
            {
                return false;
            }

            if (HasTextBom(buffer[..read]))
            {
                return false;
            }

            for (var i = 0; i < read; i++)
            {
                if (buffer[i] == 0)
                {
                    return true;
                }
            }

            return false;
        }
        finally
        {
            if (stream.CanSeek)
            {
                stream.Seek(origin, SeekOrigin.Begin);
            }
        }
    }

    private static bool HasTextBom(ReadOnlySpan<byte> buffer)
    {
        if (buffer.Length >= 3 && buffer[0] == 0xEF && buffer[1] == 0xBB && buffer[2] == 0xBF)
        {
            return true; // UTF-8 BOM
        }

        if (buffer.Length >= 2 && buffer[0] == 0xFF && buffer[1] == 0xFE)
        {
            return true; // UTF-16 LE BOM (also covers UTF-32 LE)
        }

        if (buffer.Length >= 2 && buffer[0] == 0xFE && buffer[1] == 0xFF)
        {
            return true; // UTF-16 BE BOM
        }

        if (buffer.Length >= 4 && buffer[0] == 0x00 && buffer[1] == 0x00 && buffer[2] == 0xFE && buffer[3] == 0xFF)
        {
            return true; // UTF-32 BE BOM
        }

        return false;
    }
}
