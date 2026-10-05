using Microsoft.Win32.SafeHandles;
using WirelessSecurityAnalyzer.Infrastructure.Windows.NativeWifi;

namespace WirelessSecurityAnalyzer.Infrastructure.Windows.Interop;

internal sealed class SafeWlanHandle : SafeHandleZeroOrMinusOneIsInvalid
{
    public SafeWlanHandle() : base(true) { }
    protected override bool ReleaseHandle() => NativeWifiMethods.WlanCloseHandle(handle, IntPtr.Zero) == 0;
}
