using System.Text;
using UtfUnknown;

namespace SecretsScanner.Core.IO;

/// <summary>
/// Detects file encoding (R9) for text files. Falls back to UTF-8 if the detector is
/// unconfident. Uses <a href="https://github.com/CharsetDetector/UTF-unknown">UTF.Unknown</a>.
/// </summary>
internal static class EncodingDetector
{
    static EncodingDetector()
    {
        // Required so UTF.Unknown can return Windows-1252 etc. without throwing on .NET
        // Core/.NET 5+ where the legacy code pages aren't shipped by default.
        Encoding.RegisterProvider(CodePagesEncodingProvider.Instance);
    }

    public static string ReadAllText(string path)
    {
        using var stream = File.OpenRead(path);
        return ReadAllText(stream);
    }

    public static string ReadAllText(Stream stream)
    {
        var detected = CharsetDetector.DetectFromStream(stream);
        var encoding = detected.Detected?.Encoding ?? Encoding.UTF8;
        if (stream.CanSeek)
        {
            stream.Seek(0, SeekOrigin.Begin);
        }

        using var reader = new StreamReader(stream, encoding, detectEncodingFromByteOrderMarks: true, leaveOpen: true);
        return reader.ReadToEnd();
    }
}
