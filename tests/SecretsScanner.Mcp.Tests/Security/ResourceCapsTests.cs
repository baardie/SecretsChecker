using SecretsScanner.Mcp.Security;

namespace SecretsScanner.Mcp.Tests.Security;

public sealed class ResourceCapsTests
{
    [Fact]
    public void Default_caps_match_R5_specification()
    {
        var caps = ResourceCaps.Default;

        caps.MaxFiles.Should().Be(100_000);
        caps.MaxWallClock.Should().Be(TimeSpan.FromSeconds(60));
    }

    [Fact]
    public async Task Linked_source_cancels_after_wall_clock_budget()
    {
        // Loose timing intentionally: tight thresholds flake on loaded CI runners. Poll the
        // token over a 1s window with a generous cap so the assertion is robust.
        var caps = new ResourceCaps { MaxWallClock = TimeSpan.FromMilliseconds(20) };

        using var cts = caps.CreateLinkedSource();
        var deadline = DateTime.UtcNow.AddSeconds(1);
        while (DateTime.UtcNow < deadline && !cts.IsCancellationRequested)
        {
            await Task.Delay(20);
        }

        cts.IsCancellationRequested.Should().BeTrue();
    }

    [Fact]
    public void Linked_source_also_reflects_outer_cancellation()
    {
        using var outer = new CancellationTokenSource();
        var caps = new ResourceCaps { MaxWallClock = TimeSpan.FromMinutes(5) };

        using var linked = caps.CreateLinkedSource(outer.Token);
        outer.Cancel();

        linked.IsCancellationRequested.Should().BeTrue();
    }
}
