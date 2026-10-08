using System.Runtime.InteropServices;
using WirelessSecurityAnalyzer.Core.Models;

namespace WirelessSecurityAnalyzer.Infrastructure.Windows.Interop;

[StructLayout(LayoutKind.Explicit, Size = 28)]
internal struct SockaddrInet
{
    [FieldOffset(0)] public ushort Family;
    [FieldOffset(4)] public uint Ipv4Address;
}

[StructLayout(LayoutKind.Sequential)]
internal struct IpNetRow2
{
    public SockaddrInet Address;
    public uint InterfaceIndex;
    public ulong InterfaceLuid;
    [MarshalAs(UnmanagedType.ByValArray, SizeConst = 32)] public byte[] PhysicalAddress;
    public uint PhysicalAddressLength;
    public NeighborState State;
    public byte Flags;
    public uint ReachabilityTime;
}

[StructLayout(LayoutKind.Sequential)]
internal struct IpNetTable2Header
{
    public uint NumEntries;
    public IpNetRow2 FirstRow;
}
