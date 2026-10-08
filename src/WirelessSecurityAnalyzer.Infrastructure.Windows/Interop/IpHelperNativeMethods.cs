using System.Runtime.InteropServices;

namespace WirelessSecurityAnalyzer.Infrastructure.Windows.Interop;

internal static class IpHelperNativeMethods
{
    internal const ushort AfInet = 2;
    internal const uint ErrorNotFound = 1168;

    [DllImport("iphlpapi.dll", ExactSpelling = true)]
    internal static extern uint GetIpNetTable2(ushort family, out IntPtr table);
    [DllImport("iphlpapi.dll", ExactSpelling = true)]
    internal static extern void FreeMibTable(IntPtr table);
    [DllImport("iphlpapi.dll", ExactSpelling = true)]
    internal static extern uint GetBestInterfaceEx(ref SockaddrInet destinationAddress, out uint bestInterfaceIndex);
}
