using SecretsScanner.Cli.Configuration;
using SecretsScanner.Cli.Output;
using SecretsScanner.Core.Findings;

namespace SecretsScanner.Cli.Tests.Configuration;

/// <summary>
/// R13 — layered configuration. Highest precedence: CLI flags (applied in
/// <c>Program.cs</c> after the loader returns), then env vars, repo config, user config,
/// built-in defaults. The loader covers everything below the flags layer.
/// </summary>
[Collection("EnvSerialized")]
public sealed class ConfigLoaderTests : IDisposable
{
    private readonly string _scanRoot;
    private readonly string _userConfigSandbox;
    private readonly Dictionary<string, string?> _restoreEnv = new();

    public ConfigLoaderTests()
    {
        _scanRoot = Path.Combine(Path.GetTempPath(), "secrets-scan-config-tests-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(_scanRoot);

        _userConfigSandbox = Path.Combine(Path.GetTempPath(), "secrets-scan-config-user-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(_userConfigSandbox);

        // Always start from a clean SECRETS_SCAN__ slate.
        SnapshotEnv("SECRETS_SCAN__SEVERITY");
        SnapshotEnv("SECRETS_SCAN__INCLUDEPII");
        SnapshotEnv("SECRETS_SCAN__INCLUDEHIGHENTROPY");
        SnapshotEnv("SECRETS_SCAN__BASELINE");

        // Redirect the user-config root to our sandbox so writes here don't pollute the
        // real machine config.
        if (OperatingSystem.IsWindows())
        {
            SnapshotEnv("APPDATA");
            Environment.SetEnvironmentVariable("APPDATA", _userConfigSandbox);
        }
        else
        {
            SnapshotEnv("HOME");
            Environment.SetEnvironmentVariable("HOME", _userConfigSandbox);
        }
    }

    public void Dispose()
    {
        foreach (var (key, value) in _restoreEnv)
        {
            Environment.SetEnvironmentVariable(key, value);
        }

        TryDelete(_scanRoot);
        TryDelete(_userConfigSandbox);
    }

    [Fact]
    public void Defaults_when_no_sources_present()
    {
        var options = new ConfigLoader().Load(_scanRoot);

        options.Severity.Should().Be(Severity.Medium);
        options.Format.Should().Be(OutputFormat.Console);
        options.IncludePii.Should().BeFalse();
        options.IncludeHighEntropy.Should().BeFalse();
        options.Baseline.Should().BeNull();
        options.Color.Should().Be(ColorMode.Auto);
    }

    [Fact]
    public void Repo_config_provides_values_when_no_other_sources_set()
    {
        WriteRepoConfig(_scanRoot, """
        {
          "severity": "High",
          "includePii": true,
          "baseline": ".secrets-baseline.json"
        }
        """);

        var options = new ConfigLoader().Load(_scanRoot);

        options.Severity.Should().Be(Severity.High);
        options.IncludePii.Should().BeTrue();
        options.Baseline.Should().Be(".secrets-baseline.json");
    }

    [Fact]
    public void Repo_config_search_walks_up_to_first_existing_file()
    {
        var nested = Path.Combine(_scanRoot, "src", "MyApi");
        Directory.CreateDirectory(nested);
        WriteRepoConfig(_scanRoot, """{ "severity": "Critical" }""");

        var options = new ConfigLoader().Load(nested);

        options.Severity.Should().Be(Severity.Critical);
    }

    [Fact]
    public void Repo_config_search_stops_at_dot_git_boundary()
    {
        // .git in the scan root prevents the walker from leaking out into a parent that has
        // a config it should not pick up.
        Directory.CreateDirectory(Path.Combine(_scanRoot, ".git"));

        var options = new ConfigLoader().Load(_scanRoot);

        options.Severity.Should().Be(Severity.Medium, "no config below the .git boundary");
    }

    [Fact]
    public void Env_var_beats_repo_config()
    {
        WriteRepoConfig(_scanRoot, """{ "severity": "Low" }""");
        Environment.SetEnvironmentVariable("SECRETS_SCAN__SEVERITY", "Critical");

        var options = new ConfigLoader().Load(_scanRoot);

        options.Severity.Should().Be(Severity.Critical);
    }

    [Fact]
    public void Env_var_can_set_a_boolean()
    {
        Environment.SetEnvironmentVariable("SECRETS_SCAN__INCLUDEHIGHENTROPY", "true");

        var options = new ConfigLoader().Load(_scanRoot);

        options.IncludeHighEntropy.Should().BeTrue();
    }

    [Fact]
    public void User_config_is_loaded_from_resolved_path()
    {
        WriteUserConfig("""{ "severity": "High" }""");

        var options = new ConfigLoader().Load(_scanRoot);

        options.Severity.Should().Be(Severity.High);
    }

    [Fact]
    public void Repo_config_overrides_user_config()
    {
        WriteUserConfig("""{ "severity": "Low" }""");
        WriteRepoConfig(_scanRoot, """{ "severity": "Critical" }""");

        var options = new ConfigLoader().Load(_scanRoot);

        options.Severity.Should().Be(Severity.Critical);
    }

    [Fact]
    public void Env_var_overrides_user_and_repo()
    {
        WriteUserConfig("""{ "severity": "Low" }""");
        WriteRepoConfig(_scanRoot, """{ "severity": "High" }""");
        Environment.SetEnvironmentVariable("SECRETS_SCAN__SEVERITY", "Critical");

        var options = new ConfigLoader().Load(_scanRoot);

        options.Severity.Should().Be(Severity.Critical);
    }

    [Fact]
    public void Resolved_user_config_path_lives_under_redirected_root()
    {
        var path = ConfigLoader.ResolveUserConfigPath();

        path.Should().NotBeNullOrEmpty();
        path!.Should().StartWith(_userConfigSandbox);
        path.Should().EndWith("config.json");
        path.Should().Contain("dotnet-tool-secrets-scan");
    }

    private void SnapshotEnv(string key)
    {
        _restoreEnv[key] = Environment.GetEnvironmentVariable(key);
        Environment.SetEnvironmentVariable(key, null);
    }

    private void WriteUserConfig(string contents)
    {
        var path = ConfigLoader.ResolveUserConfigPath()
            ?? throw new InvalidOperationException("user config path could not be resolved in test harness");

        Directory.CreateDirectory(Path.GetDirectoryName(path)!);
        File.WriteAllText(path, contents);
    }

    private static void WriteRepoConfig(string root, string contents)
    {
        File.WriteAllText(Path.Combine(root, "secrets-scan.json"), contents);
    }

    private static void TryDelete(string path)
    {
        try
        {
            if (Directory.Exists(path))
            {
                Directory.Delete(path, recursive: true);
            }
        }
        catch
        {
            // best effort
        }
    }
}
