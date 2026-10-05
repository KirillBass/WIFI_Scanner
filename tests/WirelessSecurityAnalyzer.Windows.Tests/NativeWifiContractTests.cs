using System.Runtime.InteropServices;
using System.Text;
using WirelessSecurityAnalyzer.Core.Common;
using WirelessSecurityAnalyzer.Core.Models;
using WirelessSecurityAnalyzer.Infrastructure.Windows.NativeWifi;

namespace WirelessSecurityAnalyzer.Windows.Tests;

public sealed class NativeWifiContractTests
{
    [Fact]
    public void NativeStructuresMatchWindowsAbi()
    {
        Assert.Equal(36, Marshal.SizeOf<Dot11Ssid>());
        Assert.Equal(532, Marshal.SizeOf<WlanInterfaceInfo>());
        Assert.Equal(256, Marshal.SizeOf<WlanRateSet>());
        Assert.Equal(360, Marshal.SizeOf<WlanBssEntry>());
        Assert.Equal(56, Marshal.OffsetOf<WlanBssEntry>(nameof(WlanBssEntry.Rssi)).ToInt32());
        Assert.Equal(92, Marshal.OffsetOf<WlanBssEntry>(nameof(WlanBssEntry.CenterFrequencyKhz)).ToInt32());
        Assert.Equal(352, Marshal.OffsetOf<WlanBssEntry>(nameof(WlanBssEntry.IeOffset)).ToInt32());
        Assert.Equal(IntPtr.Size == 8 ? 40 : 32, Marshal.SizeOf<WlanNotificationData>());
    }

    [Fact]
    public void BssMappingPreservesNativeMeasurementsAndTimestamp()
    {
        var timestamp = DateTimeOffset.UtcNow.AddSeconds(-2);
        var entry = CreateEntry("Тестовая сеть");
        entry.HostTimestamp = (ulong)timestamp.ToFileTime();
        var result = BssMapper.Map(entry, DateTimeOffset.UtcNow);
        Assert.Equal("Тестовая сеть", result.Ssid);
        Assert.Equal("00:01:AB:CD:EF:FF", result.Bssid);
        Assert.Equal(-61, result.RssiDbm);
        Assert.Equal(78u, result.LinkQuality);
        Assert.Equal(5180, result.FrequencyMhz);
        Assert.Equal(36, result.Channel);
        Assert.Equal(WifiBand.Ghz5, result.Band);
        Assert.Equal(timestamp, result.LastSeen);
        Assert.False(result.IsHidden);
    }

    [Theory]
    [InlineData(0)]
    [InlineData(8)]
    public void ZeroLengthOrZeroFilledSsidIsHidden(uint length)
    {
        var entry = CreateEntry(string.Empty);
        entry.Ssid.Length = length;
        Assert.True(BssMapper.Map(entry, DateTimeOffset.UtcNow).IsHidden);
    }

    [Fact]
    public void InvalidNativeSsidLengthIsRejected()
    {
        var entry = CreateEntry("network");
        entry.Ssid.Length = 33;
        Assert.Equal(WifiErrorKind.InvalidNativeData,
            Assert.Throws<WifiException>(() => BssMapper.Map(entry, DateTimeOffset.UtcNow)).Kind);
    }

    [Theory]
    [InlineData(5u, WifiErrorKind.AccessDenied)]
    [InlineData(1062u, WifiErrorKind.ServiceUnavailable)]
    [InlineData(0x80342002u, WifiErrorKind.RadioOff)]
    public void Win32FailuresHaveStructuredKinds(uint code, WifiErrorKind kind)
    {
        var exception = Assert.Throws<NativeWifiException>(() => NativeWifiException.ThrowIfError(code, "test"));
        Assert.Equal(kind, exception.Kind);
        Assert.Equal(code, exception.NativeCode);
    }

    private static WlanBssEntry CreateEntry(string ssid)
    {
        var encoded = Encoding.UTF8.GetBytes(ssid);
        var bytes = new byte[32];
        encoded.CopyTo(bytes, 0);
        return new WlanBssEntry
        {
            Ssid = new Dot11Ssid { Length = (uint)encoded.Length, Bytes = bytes },
            Bssid = [0, 1, 0xab, 0xcd, 0xef, 0xff], Rssi = -61, LinkQuality = 78,
            CenterFrequencyKhz = 5180000
        };
    }
}
