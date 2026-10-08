namespace WirelessSecurityAnalyzer.Infrastructure.Windows.NativeWifi;

internal enum Dot11BssType : uint { Infrastructure = 1, Independent = 2, Any = 3 }
internal enum Dot11PhyType : uint
{
    Unknown = 0, Fhss = 1, Dsss = 2, Ir = 3, Ofdm = 4, HrDsss = 5,
    Erp = 6, Ht = 7, Vht = 8, Dmg = 9, He = 10, Eht = 11
}
internal enum Dot11AuthAlgorithm : uint { Open = 1, Shared = 2 }
internal enum Dot11CipherAlgorithm : uint { None = 0, Wep40 = 1, Tkip = 2, Ccmp = 4, Wep104 = 5, Wep = 0x101 }

internal static class WlanConstants
{
    internal const uint NotificationSourceAcm = 0x00000008;
    internal const uint ScanComplete = 7;
    internal const uint ScanFail = 8;
}
