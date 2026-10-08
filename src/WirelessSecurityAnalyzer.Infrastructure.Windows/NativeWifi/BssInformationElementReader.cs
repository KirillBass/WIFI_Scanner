using System.Runtime.InteropServices;

namespace WirelessSecurityAnalyzer.Infrastructure.Windows.NativeWifi;

internal static class BssInformationElementReader
{
    internal const uint MaximumListSize = 64 * 1024 * 1024;
    internal const uint MaximumInformationElementSize = 65535;

    internal static bool IsValidList(uint totalSize, uint count)
    {
        var stride = (uint)Marshal.SizeOf<WlanBssEntry>();
        return totalSize is >= 8 and <= MaximumListSize && count <= 65536 && count <= (totalSize - 8) / stride;
    }

    internal static bool TryCopy(IntPtr list, uint totalSize, uint count, int entryOffset,
        WlanBssEntry entry, out byte[] informationElements)
    {
        informationElements = [];
        var stride = Marshal.SizeOf<WlanBssEntry>();
        if (list == IntPtr.Zero || !IsValidList(totalSize, count) || entryOffset < 8 ||
            (entryOffset - 8) % stride != 0 || (entryOffset - 8) / stride >= count) return false;
        if (entry.IeSize == 0) return true;
        // IeOffset is relative to this entry, not the WLAN_BSS_LIST header. Use wide arithmetic
        // before conversion to an IntPtr offset, and keep the IE outside the entire entry table.
        var start = (ulong)entryOffset + entry.IeOffset;
        var tableEnd = 8UL + count * (ulong)stride;
        if (entry.IeSize > MaximumInformationElementSize || start < tableEnd ||
            start > totalSize || entry.IeSize > totalSize - start) return false;
        informationElements = new byte[(int)entry.IeSize];
        Marshal.Copy(list + (int)start, informationElements, 0, informationElements.Length);
        return true;
    }
}
