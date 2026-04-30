using System.Reflection;
using System.Reflection.Metadata;
using System.Reflection.PortableExecutable;
using SecretsScanner.Core.Findings;

namespace SecretsScanner.Core.Tests.Invariants;

/// <summary>
/// Asserts that <c>SecretsScanner.Core</c> never references network-capable types from the
/// BCL (R18). The promise: zero telemetry, zero phone-home, zero network calls.
/// </summary>
public sealed class NetworkIsolationTests
{
    private static readonly string[] ForbiddenTypeRefs =
    {
        "System.Net.Http.HttpClient",
        "System.Net.Sockets.TcpClient",
        "System.Net.Sockets.Socket",
        "System.Net.WebClient",
        "System.Net.WebRequest",
        "System.Net.WebSockets.ClientWebSocket",
        "System.Net.Dns",
    };

    [Fact]
    public void Core_assembly_must_not_reference_network_types()
    {
        var assemblyPath = typeof(Finding).Assembly.Location;
        File.Exists(assemblyPath).Should().BeTrue();

        using var stream = File.OpenRead(assemblyPath);
        using var peReader = new PEReader(stream);
        var metadata = peReader.GetMetadataReader();

        var offenders = new List<string>();
        foreach (var handle in metadata.TypeReferences)
        {
            var typeRef = metadata.GetTypeReference(handle);
            var ns = metadata.GetString(typeRef.Namespace);
            var name = metadata.GetString(typeRef.Name);
            var fullName = string.IsNullOrEmpty(ns) ? name : $"{ns}.{name}";

            if (ForbiddenTypeRefs.Contains(fullName))
            {
                offenders.Add(fullName);
            }
        }

        offenders.Should().BeEmpty(
            "the Core assembly may not reference any network-capable type (R18 zero-telemetry promise)");
    }
}
