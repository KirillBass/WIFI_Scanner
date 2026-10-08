using System.ComponentModel;
using System.Net;
using System.Net.NetworkInformation;
using System.Runtime.InteropServices;
using WirelessSecurityAnalyzer.Core.Interfaces;
using WirelessSecurityAnalyzer.Core.Models;
using WirelessSecurityAnalyzer.Core.Network;
using WirelessSecurityAnalyzer.Infrastructure.Windows.Interop;

namespace WirelessSecurityAnalyzer.Infrastructure.Windows.Network;

public sealed class WindowsNeighborTableReader : INeighborTableReader
{
    public Task<IReadOnlyList<NeighborEntry>> ReadAsync(LocalNetworkInfo network, CancellationToken cancellationToken = default) =>
        Task.Run<IReadOnlyList<NeighborEntry>>(() =>
        {
            WindowsLocalNetworkService.EnsureWindows();
            cancellationToken.ThrowIfCancellationRequested();
            var table = IntPtr.Zero;
            try
            {
                var code = IpHelperNativeMethods.GetIpNetTable2(IpHelperNativeMethods.AfInet, out table);
                if (code == IpHelperNativeMethods.ErrorNotFound) return Array.AsReadOnly(Array.Empty<NeighborEntry>());
                if (code != 0)
                    throw new NetworkDiscoveryException(NetworkDiscoveryError.NeighborTableFailed,
                        $"GetIpNetTable2 failed ({code}).", new Win32Exception(unchecked((int)code)));
                if (table == IntPtr.Zero) return Array.AsReadOnly(Array.Empty<NeighborEntry>());
                return ReadTable(table, network, cancellationToken);
            }
            finally { if (table != IntPtr.Zero) IpHelperNativeMethods.FreeMibTable(table); }
        }, cancellationToken);

    internal static IReadOnlyList<NeighborEntry> ReadTable(IntPtr table, LocalNetworkInfo network, CancellationToken token)
    {
        var count = unchecked((uint)Marshal.ReadInt32(table));
        var offset = Marshal.OffsetOf<IpNetTable2Header>(nameof(IpNetTable2Header.FirstRow)).ToInt32();
        var size = Marshal.SizeOf<IpNetRow2>();
        var subnet = network.Subnet;
        var entries = new List<NeighborEntry>();
        for (uint i = 0; i < count; i++)
        {
            token.ThrowIfCancellationRequested();
            var row = Marshal.PtrToStructure<IpNetRow2>(IntPtr.Add(table, checked(offset + (int)i * size)));
            if (row.Address.Family != IpHelperNativeMethods.AfInet || row.InterfaceIndex != network.InterfaceIndex) continue;
            var ip = new IPAddress(BitConverter.GetBytes(row.Address.Ipv4Address));
            if (!subnet.ContainsHost(ip)) continue;
            PhysicalAddress? mac = row.PhysicalAddressLength == 6 ? new PhysicalAddress(row.PhysicalAddress[..6]) : null;
            if (!DeviceStateTracker.ValidMac(mac)) mac = null;
            entries.Add(new NeighborEntry(ip, mac, (int)row.InterfaceIndex, row.State, (row.Flags & 2) != 0, row.ReachabilityTime));
        }
        return entries.AsReadOnly();
    }
}
