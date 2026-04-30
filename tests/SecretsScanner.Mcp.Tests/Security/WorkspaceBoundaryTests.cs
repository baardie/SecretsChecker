using SecretsScanner.Mcp.Security;

namespace SecretsScanner.Mcp.Tests.Security;

[Collection("McpEnvSerialized")]
public sealed class WorkspaceBoundaryTests : IDisposable
{
    private readonly string _workspace;
    private readonly string? _origEnv;

    public WorkspaceBoundaryTests()
    {
        _workspace = Path.Combine(Path.GetTempPath(), "mcp-workspace-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(_workspace);
        _origEnv = Environment.GetEnvironmentVariable(WorkspaceBoundary.WorkspaceEnvVar);
        Environment.SetEnvironmentVariable(WorkspaceBoundary.WorkspaceEnvVar, _workspace);
    }

    public void Dispose()
    {
        Environment.SetEnvironmentVariable(WorkspaceBoundary.WorkspaceEnvVar, _origEnv);
        try
        {
            if (Directory.Exists(_workspace))
            {
                Directory.Delete(_workspace, recursive: true);
            }
        }
        catch
        {
            // best effort
        }
    }

    [Fact]
    public void Resolve_uses_CLAUDE_PROJECT_DIR_env_var_when_set()
    {
        var resolved = WorkspaceBoundary.Resolve();

        resolved.Root.Should().Be(_workspace.TrimEnd(Path.DirectorySeparatorChar));
    }

    [Fact]
    public void Resolve_falls_back_to_current_directory_when_env_unset()
    {
        Environment.SetEnvironmentVariable(WorkspaceBoundary.WorkspaceEnvVar, null);

        var resolved = WorkspaceBoundary.Resolve();

        resolved.Root.Should().Be(Directory.GetCurrentDirectory().TrimEnd(Path.DirectorySeparatorChar));
    }

    [Fact]
    public void Path_inside_workspace_is_allowed()
    {
        var inside = Path.Combine(_workspace, "src", "Api");
        Directory.CreateDirectory(inside);

        var decision = new WorkspaceBoundary(_workspace).Validate(inside);

        decision.Allowed.Should().BeTrue();
        decision.CanonicalPath.Should().Be(inside);
    }

    [Fact]
    public void Workspace_root_itself_is_allowed()
    {
        var decision = new WorkspaceBoundary(_workspace).Validate(_workspace);

        decision.Allowed.Should().BeTrue();
    }

    [Fact]
    public void Path_outside_workspace_is_denied_by_default()
    {
        var outside = Path.GetTempPath();

        var decision = new WorkspaceBoundary(_workspace).Validate(outside);

        decision.Allowed.Should().BeFalse();
        decision.Reason.Should().Contain("outside workspace");
        decision.Reason.Should().Contain("allowOutsideWorkspace");
    }

    [Fact]
    public void Path_outside_workspace_can_be_allowed_with_override()
    {
        var outside = Path.GetTempPath();

        var decision = new WorkspaceBoundary(_workspace).Validate(outside, allowOutsideWorkspace: true);

        decision.Allowed.Should().BeTrue();
    }

    [Fact]
    public void Empty_path_is_denied()
    {
        var decision = new WorkspaceBoundary(_workspace).Validate("");

        decision.Allowed.Should().BeFalse();
        decision.Reason.Should().Contain("empty");
    }

    [Fact]
    public void Relative_path_is_canonicalised_relative_to_cwd_then_validated()
    {
        // "." resolves to the current working directory; if we redirect cwd into the
        // workspace, "." should be allowed. Otherwise it would point outside.
        var origCwd = Directory.GetCurrentDirectory();
        try
        {
            Directory.SetCurrentDirectory(_workspace);
            var decision = new WorkspaceBoundary(_workspace).Validate(".");

            decision.Allowed.Should().BeTrue();
        }
        finally
        {
            Directory.SetCurrentDirectory(origCwd);
        }
    }

    [Fact]
    public void Windows_drive_root_is_on_the_system_denylist()
    {
        if (!OperatingSystem.IsWindows())
        {
            return;
        }

        var decision = new WorkspaceBoundary(_workspace).Validate(@"C:\", allowOutsideWorkspace: true);

        decision.Allowed.Should().BeFalse();
        decision.Reason.Should().Contain("system denylist");
    }

    [Fact]
    public void Windows_program_files_is_denied_even_with_override()
    {
        if (!OperatingSystem.IsWindows())
        {
            return;
        }

        var decision = new WorkspaceBoundary(_workspace).Validate(
            @"C:\Program Files\dotnet", allowOutsideWorkspace: true);

        decision.Allowed.Should().BeFalse();
        decision.Reason.Should().Contain("system denylist");
    }

    [Fact]
    public void Windows_other_users_home_is_denied_even_with_override()
    {
        if (!OperatingSystem.IsWindows())
        {
            return;
        }

        var decision = new WorkspaceBoundary(_workspace).Validate(
            @"C:\Users\someone-else", allowOutsideWorkspace: true);

        decision.Allowed.Should().BeFalse();
        decision.Reason.Should().Contain("system denylist");
    }

    [Fact]
    public void Windows_current_users_home_is_allowed_with_override()
    {
        if (!OperatingSystem.IsWindows())
        {
            return;
        }

        var home = Environment.GetEnvironmentVariable("USERPROFILE")!;

        var decision = new WorkspaceBoundary(_workspace).Validate(home, allowOutsideWorkspace: true);

        decision.Allowed.Should().BeTrue("the current user's home is excluded from the denylist");
    }

    [Fact]
    public void Posix_etc_is_on_the_system_denylist()
    {
        if (OperatingSystem.IsWindows())
        {
            return;
        }

        var decision = new WorkspaceBoundary(_workspace).Validate("/etc/passwd", allowOutsideWorkspace: true);

        decision.Allowed.Should().BeFalse();
        decision.Reason.Should().Contain("system denylist");
    }
}
