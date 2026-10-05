using WirelessSecurityAnalyzer.Core.Common;

namespace WirelessSecurityAnalyzer.Infrastructure.Windows.NativeWifi;

public sealed class NativeWifiException : WifiException
{
    public uint NativeCode { get; }
    public string Operation { get; }

    internal NativeWifiException(uint code, string operation)
        : base(MapKind(code), $"{operation} failed (native code {code}).")
    {
        NativeCode = code;
        Operation = operation;
    }

    internal static void ThrowIfError(uint code, string operation)
    {
        if (code != 0) throw new NativeWifiException(code, operation);
    }

    private static WifiErrorKind MapKind(uint code) => code switch
    {
        5 => WifiErrorKind.AccessDenied,
        1062 => WifiErrorKind.ServiceUnavailable,
        0x80342002 => WifiErrorKind.RadioOff,
        1168 => WifiErrorKind.NoAdapter,
        _ => WifiErrorKind.ScanFailed
    };
}
