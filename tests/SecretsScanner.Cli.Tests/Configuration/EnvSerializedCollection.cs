namespace SecretsScanner.Cli.Tests.Configuration;

/// <summary>
/// Disables xUnit's default parallel execution for tests that mutate process-wide
/// environment variables (config ladder, colour resolution).
/// </summary>
[CollectionDefinition("EnvSerialized", DisableParallelization = true)]
public sealed class EnvSerializedCollection
{
}
