namespace WirelessSecurityAnalyzer.Infrastructure.Windows.NativeWifi;

internal enum Dot11BssType : uint { Infrastructure = 1, Independent = 2, Any = 3 }

internal static class WlanConstants
{
    internal const uint NotificationSourceAcm = 0x00000008;
    internal const uint ScanComplete = 7;
    internal const uint ScanFail = 8;
}
