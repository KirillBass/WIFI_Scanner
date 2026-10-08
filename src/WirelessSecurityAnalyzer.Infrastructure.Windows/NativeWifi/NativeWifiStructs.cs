using System.Runtime.InteropServices;
using WirelessSecurityAnalyzer.Core.Models;

namespace WirelessSecurityAnalyzer.Infrastructure.Windows.NativeWifi;

[StructLayout(LayoutKind.Sequential)]
internal struct Dot11Ssid
{
    public uint Length;
    [MarshalAs(UnmanagedType.ByValArray, SizeConst = 32)] public byte[] Bytes;
}

[StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
internal struct WlanInterfaceInfo
{
    public Guid Id;
    [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 256)] public string Description;
    public WifiAdapterState State;
}

[StructLayout(LayoutKind.Sequential)]
internal struct WlanRateSet
{
    public uint Length;
    [MarshalAs(UnmanagedType.ByValArray, SizeConst = 126)] public ushort[] Rates;
}

[StructLayout(LayoutKind.Sequential)]
internal struct WlanBssEntry
{
    public Dot11Ssid Ssid;
    public uint PhyId;
    [MarshalAs(UnmanagedType.ByValArray, SizeConst = 6)] public byte[] Bssid;
    public Dot11BssType BssType;
    public uint PhyType;
    public int Rssi;
    public uint LinkQuality;
    public byte InRegDomain;
    public ushort BeaconPeriod;
    public ulong Timestamp;
    public ulong HostTimestamp;
    public ushort CapabilityInformation;
    public uint CenterFrequencyKhz;
    public WlanRateSet RateSet;
    public uint IeOffset;
    public uint IeSize;
}

[StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
internal struct WlanAvailableNetwork
{
    [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 256)] public string ProfileName;
    public Dot11Ssid Ssid;
    public Dot11BssType BssType;
    public uint NumberOfBssids;
    public uint NetworkConnectable;
    public uint NotConnectableReason;
    public uint NumberOfPhyTypes;
    [MarshalAs(UnmanagedType.ByValArray, SizeConst = 8)] public uint[] PhyTypes;
    public uint MorePhyTypes;
    public uint SignalQuality;
    public uint SecurityEnabled;
    public Dot11AuthAlgorithm DefaultAuthAlgorithm;
    public Dot11CipherAlgorithm DefaultCipherAlgorithm;
    public uint Flags;
    public uint Reserved;
}

[StructLayout(LayoutKind.Sequential)]
internal struct WlanNotificationData
{
    public uint Source;
    public uint Code;
    public Guid InterfaceId;
    public uint DataSize;
    public IntPtr Data;
}
