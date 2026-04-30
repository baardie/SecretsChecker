namespace SecretsScanner.Mcp.Tests.Security;

/// <summary>
/// MCP-side env-mutating tests serialise on this name. The CLI tests have a parallel
/// <c>EnvSerialized</c> collection; the names are intentionally distinct so xUnit never
/// merges the two even if assemblies ever co-host in the same process.
/// </summary>
[CollectionDefinition("McpEnvSerialized", DisableParallelization = true)]
public sealed class EnvSerializedCollection
{
}
