namespace WirelessSecurityAnalyzer.Core.Common;

public enum WifiErrorKind
{
    UnsupportedPlatform, NoAdapter, RadioOff, ServiceUnavailable,
    AccessDenied, Timeout, ScanFailed, InvalidNativeData
}

public class WifiException(WifiErrorKind kind, string message, Exception? innerException = null)
    : Exception(message, innerException)
{
    public WifiErrorKind Kind { get; } = kind;
}
