using System.Text.Json;
using ModelContextProtocol.Client;
using ModelContextProtocol.Protocol;
using SecretsScanner.Mcp.Security;

namespace SecretsScanner.Mcp.Tests.Integration;

/// <summary>
/// True end-to-end test: spawn the actual MCP server binary, drive it over stdio with the
/// SDK client, and verify both tools are registered and callable. CLAUDE_PROJECT_DIR is
/// pointed at our temp workspace so the server's <see cref="Security.WorkspaceBoundary"/>
/// allows path arguments under it.
/// </summary>
[Collection("McpServer")]
public sealed class McpServerIntegrationTests : IAsyncLifetime, IDisposable
{
    private readonly string _workspace;

    public McpServerIntegrationTests()
    {
        _workspace = Path.Combine(Path.GetTempPath(), "mcp-integration-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(_workspace);
    }

    public Task InitializeAsync() => Task.CompletedTask;
    public Task DisposeAsync() => Task.CompletedTask;

    public void Dispose()
    {
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
    public async Task Server_lists_both_tools()
    {
        await using var client = await ConnectAsync();

        var tools = await client.ListToolsAsync();

        var names = tools.Select(t => t.Name).ToArray();
        names.Should().Contain("scan_for_secrets");
        names.Should().Contain("scan_git_history");
    }

    [Fact]
    public async Task Scan_for_secrets_returns_a_finding_without_authorName_or_entropy()
    {
        File.WriteAllText(Path.Combine(_workspace, "Program.cs"), "var k = \"AKIAIOSFODNN7EXAMPLE\";");

        await using var client = await ConnectAsync();

        var args = new Dictionary<string, object?>
        {
            ["path"] = _workspace,
            ["severity"] = "medium",
        };
        var result = await client.CallToolAsync("scan_for_secrets", args);

        // SDK convention: IsError is nullable; null or false both indicate success. Use a
        // boolean coercion so a future SDK change to non-null doesn't accidentally turn this
        // assertion vacuous.
        (result.IsError ?? false).Should().BeFalse();

        var json = ExtractJsonText(result);
        json.Should().Contain("\"AwsAccessKey\"");
        json.Should().Contain("\"hint\":\"AwsAccessKey=***\"");
        json.Should().NotContain("authorName");
        json.Should().NotContain("entropy");
        json.Should().NotContain("AKIAIOSFODNN7EXAMPLE", "raw secret value must never appear in MCP output");
    }

    [Fact]
    public async Task Scan_for_secrets_rejects_path_outside_workspace()
    {
        await using var client = await ConnectAsync();

        var args = new Dictionary<string, object?>
        {
            ["path"] = Path.GetTempPath(),
            ["severity"] = "medium",
        };
        var result = await client.CallToolAsync("scan_for_secrets", args);

        var json = ExtractJsonText(result);
        json.Should().Contain("outside workspace");
    }

    [Fact]
    public async Task Scan_git_history_against_non_git_path_returns_a_structured_error()
    {
        await using var client = await ConnectAsync();

        var args = new Dictionary<string, object?>
        {
            ["path"] = _workspace,
            ["severity"] = "medium",
        };
        var result = await client.CallToolAsync("scan_git_history", args);

        var json = ExtractJsonText(result);
        json.Should().Contain("not a git repository");
    }

    private async Task<McpClient> ConnectAsync()
    {
        var dll = Path.Combine(AppContext.BaseDirectory, "tool-secrets-scan-mcp.dll");

        var transport = new StdioClientTransport(new StdioClientTransportOptions
        {
            Name = "secrets-scan-mcp",
            Command = "dotnet",
            Arguments = new[] { dll },
            EnvironmentVariables = new Dictionary<string, string?>
            {
                [WorkspaceBoundary.WorkspaceEnvVar] = _workspace,
            },
        });

        return await McpClient.CreateAsync(transport);
    }

    private static string ExtractJsonText(CallToolResult result)
    {
        // The SDK serialises non-string return values into a "text" content block whose body
        // is the JSON of the response object. Concatenating all text blocks gives us the wire
        // shape Claude would observe.
        var sb = new System.Text.StringBuilder();
        foreach (var content in result.Content)
        {
            if (content is TextContentBlock text)
            {
                sb.Append(text.Text);
            }
        }
        return sb.ToString();
    }
}

[CollectionDefinition("McpServer", DisableParallelization = true)]
public sealed class McpServerCollection
{
}
