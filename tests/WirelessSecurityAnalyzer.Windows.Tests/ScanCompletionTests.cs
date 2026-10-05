using WirelessSecurityAnalyzer.Core.Common;
using WirelessSecurityAnalyzer.Infrastructure.Windows.NativeWifi;

namespace WirelessSecurityAnalyzer.Windows.Tests;

public sealed class ScanCompletionTests
{
    [Fact]
    public async Task CompletionBeforeWaitIsNotLost()
    {
        var completion = new ScanCompletion();
        completion.Complete();
        await completion.WaitAsync(TimeSpan.FromSeconds(1), CancellationToken.None);
    }

    [Fact]
    public async Task CompletionAfterWaitFinishesPendingTask()
    {
        var completion = new ScanCompletion();
        var waiting = completion.WaitAsync(TimeSpan.FromSeconds(1), CancellationToken.None);
        Assert.False(waiting.IsCompleted);
        completion.Complete();
        await waiting;
    }

    [Fact]
    public async Task FailureNotificationReturnsError()
    {
        var completion = new ScanCompletion();
        completion.Complete(123);
        var exception = await Assert.ThrowsAsync<WifiException>(() => completion.WaitAsync(TimeSpan.FromSeconds(1), CancellationToken.None));
        Assert.Equal(WifiErrorKind.ScanFailed, exception.Kind);
    }

    [Fact]
    public async Task MissingNotificationTimesOut()
    {
        var completion = new ScanCompletion();
        var exception = await Assert.ThrowsAsync<WifiException>(() => completion.WaitAsync(TimeSpan.FromMilliseconds(30), CancellationToken.None));
        Assert.Equal(WifiErrorKind.Timeout, exception.Kind);
    }

    [Fact]
    public async Task CancellationDoesNotWaitForTimeout()
    {
        var completion = new ScanCompletion();
        using var source = new CancellationTokenSource();
        var waiting = completion.WaitAsync(TimeSpan.FromSeconds(30), source.Token);
        source.Cancel();
        await Assert.ThrowsAnyAsync<OperationCanceledException>(() => waiting);
    }

    [Fact]
    public async Task DuplicateOrLateNotificationsAreHarmless()
    {
        var completion = new ScanCompletion();
        completion.Complete();
        completion.Complete(123);
        await completion.WaitAsync(TimeSpan.FromSeconds(1), CancellationToken.None);
    }
}
