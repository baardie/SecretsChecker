using Microsoft.Extensions.Configuration;

namespace SecretsScanner.Cli.Configuration;

/// <summary>
/// Layered configuration loader (R13). Highest precedence first:
///   1. CLI flags                        — applied by the caller after this returns
///   2. Environment variables            — <c>SECRETS_SCAN__*</c> (.NET nesting convention)
///   3. Repo config                      — <c>secrets-scan.json</c> at the scan root
///   4. User config                      — <c>~/.config/dotnet-tool-secrets-scan/config.json</c>
///                                         or <c>%APPDATA%\dotnet-tool-secrets-scan\config.json</c>
///   5. Built-in defaults                — the <see cref="CliOptions"/> record's defaults
/// </summary>
public sealed class ConfigLoader
{
    public const string EnvPrefix = "SECRETS_SCAN__";
    public const string ConfigFileName = "secrets-scan.json";
    public const string AppDirName = "dotnet-tool-secrets-scan";

    public CliOptions Load(string scanRoot)
    {
        var builder = new ConfigurationBuilder();

        var userConfigPath = ResolveUserConfigPath();
        if (userConfigPath is not null && File.Exists(userConfigPath))
        {
            builder.AddJsonFile(userConfigPath, optional: true, reloadOnChange: false);
        }

        // ResolveRepoConfigPath now only returns a path when the file actually exists, so
        // the second File.Exists check the loader used to do is no longer needed.
        var repoConfigPath = ResolveRepoConfigPath(scanRoot);
        if (repoConfigPath is not null)
        {
            builder.AddJsonFile(repoConfigPath, optional: true, reloadOnChange: false);
        }

        builder.AddEnvironmentVariables(EnvPrefix);

        var configuration = builder.Build();
        var options = configuration.Get<CliOptions>() ?? new CliOptions();
        return options;
    }

    public static string? ResolveUserConfigPath()
    {
        if (OperatingSystem.IsWindows())
        {
            // APPDATA env var first so callers (and tests) can redirect; the SpecialFolder
            // API on Windows ignores the env var and reads from the registry.
            var appData = Environment.GetEnvironmentVariable("APPDATA")
                ?? Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData);
            return string.IsNullOrEmpty(appData) ? null : Path.Combine(appData, AppDirName, "config.json");
        }

        var home = Environment.GetEnvironmentVariable("HOME")
            ?? Environment.GetFolderPath(Environment.SpecialFolder.UserProfile);
        return string.IsNullOrEmpty(home) ? null : Path.Combine(home, ".config", AppDirName, "config.json");
    }

    /// <summary>
    /// Walks up from <paramref name="scanRoot"/> looking for a <c>secrets-scan.json</c>; stops
    /// at the first existing file or at the repository root (the directory containing
    /// <c>.git</c>). Returns <c>null</c> if no config file exists in that range — callers can
    /// treat the return value as authoritative without re-checking <see cref="File.Exists"/>.
    /// </summary>
    public static string? ResolveRepoConfigPath(string scanRoot)
    {
        var current = Path.GetFullPath(scanRoot);
        while (!string.IsNullOrEmpty(current))
        {
            var candidate = Path.Combine(current, ConfigFileName);
            if (File.Exists(candidate))
            {
                return candidate;
            }

            if (Directory.Exists(Path.Combine(current, ".git")))
            {
                // Reached the repository root without finding a config; stop walking up.
                return null;
            }

            var parent = Directory.GetParent(current);
            if (parent is null)
            {
                return null;
            }

            current = parent.FullName;
        }

        return null;
    }
}
