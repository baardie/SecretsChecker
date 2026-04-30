using SecretsScanner.Cli.Hooks;

namespace SecretsScanner.Cli.Tests.Hooks;

/// <summary>
/// R11 — never silently overwrite. Each known hook manager produces guidance instead of a
/// write; unknown hooks require explicit --append or --force; uninstall removes only our
/// marker block.
/// </summary>
public sealed class PreCommitHookInstallerTests : IDisposable
{
    private readonly string _repo;

    public PreCommitHookInstallerTests()
    {
        _repo = Path.Combine(Path.GetTempPath(), "secrets-scan-hook-tests-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(_repo);
    }

    public void Dispose()
    {
        try
        {
            if (Directory.Exists(_repo))
            {
                Directory.Delete(_repo, recursive: true);
            }
        }
        catch
        {
            // best-effort temp cleanup
        }
    }

    [Fact]
    public void Install_without_dot_git_reports_not_a_git_repo()
    {
        var installer = new PreCommitHookInstaller(_repo);

        var result = installer.Install(InstallMode.Refuse);

        result.Outcome.Should().Be(InstallOutcome.NotAGitRepo);
        File.Exists(HookPath()).Should().BeFalse();
    }

    [Fact]
    public void Install_with_no_existing_hook_writes_fresh_marker_block()
    {
        InitGit();
        var installer = new PreCommitHookInstaller(_repo);

        var result = installer.Install(InstallMode.Refuse);

        result.Outcome.Should().Be(InstallOutcome.WroteFresh);
        var content = File.ReadAllText(HookPath());
        content.Should().Contain("# >>> dotnet-tool-secrets-scan >>>");
        content.Should().Contain("# <<< dotnet-tool-secrets-scan <<<");
        content.Should().Contain("dotnet tool-secrets-scan --severity high");
    }

    [Fact]
    public void Install_with_existing_marker_block_is_idempotent()
    {
        InitGit();
        new PreCommitHookInstaller(_repo).Install(InstallMode.Refuse);

        var second = new PreCommitHookInstaller(_repo).Install(InstallMode.Refuse);

        second.Outcome.Should().Be(InstallOutcome.AlreadyInstalled);
    }

    [Fact]
    public void Install_with_unknown_hook_in_refuse_mode_does_not_modify()
    {
        InitGit();
        WriteHook("#!/bin/sh\necho hi\n");

        var result = new PreCommitHookInstaller(_repo).Install(InstallMode.Refuse);

        result.Outcome.Should().Be(InstallOutcome.RefusedExistingHook);
        File.ReadAllText(HookPath()).Should().Be("#!/bin/sh\necho hi\n");
        File.Exists(HookPath() + ".bak").Should().BeFalse();
    }

    [Fact]
    public void Install_with_unknown_hook_in_append_mode_adds_marker_block()
    {
        InitGit();
        WriteHook("#!/bin/sh\necho hi\n");

        var result = new PreCommitHookInstaller(_repo).Install(InstallMode.Append);

        result.Outcome.Should().Be(InstallOutcome.AppendedToExisting);
        var content = File.ReadAllText(HookPath());
        content.Should().StartWith("#!/bin/sh\necho hi\n");
        content.Should().Contain("# >>> dotnet-tool-secrets-scan >>>");
        content.Should().Contain("# <<< dotnet-tool-secrets-scan <<<");
    }

    [Fact]
    public void Install_with_unknown_hook_in_force_mode_writes_backup()
    {
        InitGit();
        WriteHook("#!/bin/sh\necho hi\n");

        var result = new PreCommitHookInstaller(_repo).Install(InstallMode.Force);

        result.Outcome.Should().Be(InstallOutcome.OverwroteWithBackup);
        File.Exists(HookPath() + ".bak").Should().BeTrue();
        File.ReadAllText(HookPath() + ".bak").Should().Be("#!/bin/sh\necho hi\n");
        File.ReadAllText(HookPath()).Should().Contain("# >>> dotnet-tool-secrets-scan >>>");
    }

    [Fact]
    public void Husky_via_package_json_is_detected_and_no_hook_is_written()
    {
        InitGit();
        File.WriteAllText(Path.Combine(_repo, "package.json"), "{ \"devDependencies\": { \"husky\": \"^9\" } }");

        var result = new PreCommitHookInstaller(_repo).Install(InstallMode.Refuse);

        result.Outcome.Should().Be(InstallOutcome.DelegatedToKnownManager);
        result.Manager.Should().Be(KnownHookManager.Husky);
        File.Exists(HookPath()).Should().BeFalse();
    }

    [Fact]
    public void Husky_via_dot_husky_directory_is_detected()
    {
        InitGit();
        Directory.CreateDirectory(Path.Combine(_repo, ".husky"));

        PreCommitHookInstaller.DetectKnownManager(_repo).Should().Be(KnownHookManager.Husky);
    }

    [Fact]
    public void Lefthook_via_yml_is_detected()
    {
        InitGit();
        File.WriteAllText(Path.Combine(_repo, "lefthook.yml"), "pre-commit:\n  commands: {}\n");

        PreCommitHookInstaller.DetectKnownManager(_repo).Should().Be(KnownHookManager.Lefthook);
    }

    [Fact]
    public void Lefthook_via_yaml_is_detected()
    {
        InitGit();
        File.WriteAllText(Path.Combine(_repo, "lefthook.yaml"), "pre-commit:\n  commands: {}\n");

        PreCommitHookInstaller.DetectKnownManager(_repo).Should().Be(KnownHookManager.Lefthook);
    }

    [Fact]
    public void PreCommit_framework_is_detected()
    {
        InitGit();
        File.WriteAllText(Path.Combine(_repo, ".pre-commit-config.yaml"), "repos: []\n");

        PreCommitHookInstaller.DetectKnownManager(_repo).Should().Be(KnownHookManager.PreCommitFramework);
    }

    [Fact]
    public void Unknown_repo_returns_no_known_manager()
    {
        InitGit();
        File.WriteAllText(Path.Combine(_repo, "package.json"), "{ \"devDependencies\": { \"react\": \"^18\" } }");

        PreCommitHookInstaller.DetectKnownManager(_repo).Should().BeNull();
    }

    [Theory]
    [InlineData(KnownHookManager.Husky)]
    [InlineData(KnownHookManager.Lefthook)]
    [InlineData(KnownHookManager.PreCommitFramework)]
    public void GuidanceFor_returns_paste_ready_snippet_per_manager(KnownHookManager manager)
    {
        var guidance = PreCommitHookInstaller.GuidanceFor(manager);

        guidance.Should().NotBeNullOrWhiteSpace();
        guidance.Should().Contain("dotnet tool-secrets-scan --severity high");
    }

    [Fact]
    public void Uninstall_when_no_hook_present_reports_not_installed()
    {
        InitGit();

        var result = new PreCommitHookInstaller(_repo).Uninstall();

        result.Outcome.Should().Be(InstallOutcome.NotInstalled);
    }

    [Fact]
    public void Uninstall_when_only_our_marker_block_present_removes_file()
    {
        InitGit();
        new PreCommitHookInstaller(_repo).Install(InstallMode.Refuse);

        var result = new PreCommitHookInstaller(_repo).Uninstall();

        result.Outcome.Should().Be(InstallOutcome.RemovedFile);
        File.Exists(HookPath()).Should().BeFalse();
    }

    [Fact]
    public void Uninstall_when_marker_block_co_exists_with_other_content_keeps_other_content()
    {
        InitGit();
        WriteHook("#!/bin/sh\necho hi\n");
        new PreCommitHookInstaller(_repo).Install(InstallMode.Append);

        var result = new PreCommitHookInstaller(_repo).Uninstall();

        result.Outcome.Should().Be(InstallOutcome.RemovedMarkerBlock);
        var content = File.ReadAllText(HookPath());
        content.Should().NotContain("dotnet-tool-secrets-scan");
        content.Should().Contain("echo hi");
    }

    [Fact]
    public void Uninstall_when_hook_has_no_marker_block_reports_not_installed()
    {
        InitGit();
        WriteHook("#!/bin/sh\necho hi\n");

        var result = new PreCommitHookInstaller(_repo).Uninstall();

        result.Outcome.Should().Be(InstallOutcome.NotInstalled);
        File.ReadAllText(HookPath()).Should().Be("#!/bin/sh\necho hi\n");
    }

    private string HookPath() => Path.Combine(_repo, ".git", "hooks", "pre-commit");

    private void InitGit() => Directory.CreateDirectory(Path.Combine(_repo, ".git"));

    private void WriteHook(string content)
    {
        var dir = Path.Combine(_repo, ".git", "hooks");
        Directory.CreateDirectory(dir);
        File.WriteAllText(Path.Combine(dir, "pre-commit"), content);
    }
}
