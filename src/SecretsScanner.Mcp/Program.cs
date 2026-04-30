using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;
using SecretsScanner.Mcp.Security;
using SecretsScanner.Mcp.Tools;

namespace SecretsScanner.Mcp;

internal static class Program
{
    public static async Task Main(string[] args)
    {
        var builder = Host.CreateApplicationBuilder(args);

        // MCP servers run over stdio: stdout is reserved for protocol traffic, so all logs
        // must go to stderr. Without this, Claude Code's parser sees log lines as malformed
        // protocol messages and the connection drops.
        builder.Logging.ClearProviders();
        builder.Logging.AddConsole(options => options.LogToStandardErrorThreshold = LogLevel.Trace);

        builder.Services.AddSingleton(WorkspaceBoundary.Resolve());
        builder.Services.AddSingleton(ResourceCaps.Default);
        builder.Services.AddSingleton<ScanForSecretsTool>();
        builder.Services.AddSingleton<ScanGitHistoryTool>();

        builder.Services
            .AddMcpServer()
            .WithStdioServerTransport()
            .WithToolsFromAssembly();

        await builder.Build().RunAsync().ConfigureAwait(false);
    }
}
