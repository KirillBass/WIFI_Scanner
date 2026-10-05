using WirelessSecurityAnalyzer.Core.Common;

namespace WirelessSecurityAnalyzer.Infrastructure.Windows.NativeWifi;

/// <summary>One scan request. Continuations never execute inside a WLAN callback.</summary>
internal sealed class ScanCompletion
{
    private readonly TaskCompletionSource<uint> _source = new(TaskCreationOptions.RunContinuationsAsynchronously);

    public void Complete(uint reasonCode = 0) => _source.TrySetResult(reasonCode);
    public void Fail(Exception exception) => _source.TrySetException(exception);

    public async Task WaitAsync(TimeSpan timeout, CancellationToken cancellationToken)
    {
        uint reason;
        try
        {
            reason = await _source.Task.WaitAsync(timeout, cancellationToken).ConfigureAwait(false);
        }
        catch (TimeoutException exception)
        {
            throw new WifiException(WifiErrorKind.Timeout, "WLAN scan notification timed out.", exception);
        }

        if (reason != 0)
            throw new WifiException(WifiErrorKind.ScanFailed, $"WLAN scan failed (reason {reason}).");
    }
}
