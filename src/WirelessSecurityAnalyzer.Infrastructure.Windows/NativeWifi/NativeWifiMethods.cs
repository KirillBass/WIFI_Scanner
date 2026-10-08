using System.Runtime.InteropServices;
using WirelessSecurityAnalyzer.Infrastructure.Windows.Interop;

namespace WirelessSecurityAnalyzer.Infrastructure.Windows.NativeWifi;

internal static class NativeWifiMethods
{
    [UnmanagedFunctionPointer(CallingConvention.Winapi)]
    internal delegate void NotificationCallback(ref WlanNotificationData data, IntPtr context);

    [DllImport("wlanapi.dll", ExactSpelling = true)]
    internal static extern uint WlanOpenHandle(uint version, IntPtr reserved, out uint negotiatedVersion, out SafeWlanHandle handle);

    [DllImport("wlanapi.dll", ExactSpelling = true)]
    internal static extern uint WlanCloseHandle(IntPtr handle, IntPtr reserved);

    [DllImport("wlanapi.dll", ExactSpelling = true)]
    internal static extern uint WlanEnumInterfaces(SafeWlanHandle handle, IntPtr reserved, out IntPtr list);

    [DllImport("wlanapi.dll", ExactSpelling = true)]
    internal static extern uint WlanScan(SafeWlanHandle handle, in Guid interfaceId, IntPtr ssid, IntPtr ieData, IntPtr reserved);

    [DllImport("wlanapi.dll", ExactSpelling = true)]
    internal static extern uint WlanRegisterNotification(SafeWlanHandle handle, uint source,
        [MarshalAs(UnmanagedType.Bool)] bool ignoreDuplicate, NotificationCallback? callback,
        IntPtr context, IntPtr reserved, out uint previousSource);

    [DllImport("wlanapi.dll", ExactSpelling = true)]
    internal static extern uint WlanGetNetworkBssList(SafeWlanHandle handle, in Guid interfaceId,
        IntPtr ssid, Dot11BssType bssType, [MarshalAs(UnmanagedType.Bool)] bool securityEnabled,
        IntPtr reserved, out IntPtr list);

    [DllImport("wlanapi.dll", ExactSpelling = true)]
    internal static extern uint WlanGetAvailableNetworkList(SafeWlanHandle handle, in Guid interfaceId,
        uint flags, IntPtr reserved, out IntPtr list);

    [DllImport("wlanapi.dll", ExactSpelling = true)]
    internal static extern void WlanFreeMemory(IntPtr memory);
}
