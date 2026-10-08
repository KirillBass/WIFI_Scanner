using System.Collections.Concurrent;
using System.Net.NetworkInformation;
using System.Runtime.InteropServices;
using Serilog;
using WirelessSecurityAnalyzer.Core.Common;
using WirelessSecurityAnalyzer.Core.Analysis.Wifi;
using WirelessSecurityAnalyzer.Core.Models;
using WirelessSecurityAnalyzer.Infrastructure.Windows.Interop;
using WirelessSecurityAnalyzer.Infrastructure.Windows.Network.Identity;

namespace WirelessSecurityAnalyzer.Infrastructure.Windows.NativeWifi;

internal sealed class NativeWifiClient : IDisposable
{
    private readonly SafeWlanHandle _handle;
    private readonly NativeWifiMethods.NotificationCallback _callback;
    private readonly ConcurrentDictionary<Guid, ScanCompletion> _pending = new();
    private readonly ILogger _logger;
    private readonly MacVendorResolver _vendorResolver;
    private bool _registered;
    private bool _disposed;

    internal NativeWifiClient(ILogger logger, MacVendorResolver vendorResolver)
    {
        if (!OperatingSystem.IsWindows())
            throw new WifiException(WifiErrorKind.UnsupportedPlatform, "Native Wi-Fi requires Windows 10/11.");
        _logger = logger;
        _vendorResolver = vendorResolver;
        _callback = OnNotification;
        var result = NativeWifiMethods.WlanOpenHandle(2, IntPtr.Zero, out _, out _handle);
        if (result != 0)
        {
            _handle.Dispose();
            throw new NativeWifiException(result, nameof(NativeWifiMethods.WlanOpenHandle));
        }
    }

    internal IReadOnlyList<WifiAdapter> GetAdapters()
    {
        NativeWifiException.ThrowIfError(NativeWifiMethods.WlanEnumInterfaces(_handle, IntPtr.Zero, out var buffer),
            nameof(NativeWifiMethods.WlanEnumInterfaces));
        try
        {
            var count = Marshal.ReadInt32(buffer);
            if (count is < 0 or > 256)
                throw new WifiException(WifiErrorKind.InvalidNativeData, "Invalid WLAN interface count.");
            var adapters = new List<WifiAdapter>(count);
            var stride = Marshal.SizeOf<WlanInterfaceInfo>();
            for (var i = 0; i < count; i++)
            {
                var entry = Marshal.PtrToStructure<WlanInterfaceInfo>(buffer + 8 + i * stride);
                adapters.Add(new WifiAdapter(entry.Id, entry.Description, entry.State));
            }
            return adapters.AsReadOnly();
        }
        finally { NativeWifiMethods.WlanFreeMemory(buffer); }
    }

    internal async Task<IReadOnlyList<WifiAccessPoint>> ScanAsync(WifiAdapter adapter, TimeSpan timeout, CancellationToken token)
    {
        token.ThrowIfCancellationRequested();
        if (!_registered)
        {
            NativeWifiException.ThrowIfError(NativeWifiMethods.WlanRegisterNotification(_handle,
                WlanConstants.NotificationSourceAcm, false, _callback, IntPtr.Zero, IntPtr.Zero, out _),
                nameof(NativeWifiMethods.WlanRegisterNotification));
            _registered = true;
        }

        var completion = new ScanCompletion();
        if (!_pending.TryAdd(adapter.Id, completion))
            throw new InvalidOperationException("A scan is already pending for this adapter.");
        try
        {
            NativeWifiException.ThrowIfError(NativeWifiMethods.WlanScan(_handle, adapter.Id, IntPtr.Zero, IntPtr.Zero, IntPtr.Zero),
                nameof(NativeWifiMethods.WlanScan));
            await completion.WaitAsync(timeout, token).ConfigureAwait(false);
            token.ThrowIfCancellationRequested();
            return ReadBssList(adapter.Id);
        }
        finally { _pending.TryRemove(adapter.Id, out _); }
    }

    private IReadOnlyList<WifiAccessPoint> ReadBssList(Guid interfaceId)
    {
        // With a null SSID, securityEnabled is ignored and open/protected BSSs are both returned.
        NativeWifiException.ThrowIfError(NativeWifiMethods.WlanGetNetworkBssList(_handle, interfaceId,
            IntPtr.Zero, Dot11BssType.Any, false, IntPtr.Zero, out var buffer), nameof(NativeWifiMethods.WlanGetNetworkBssList));
        try
        {
            if (buffer == IntPtr.Zero)
                throw new WifiException(WifiErrorKind.InvalidNativeData, "The WLAN BSS list is missing.");
            var totalSize = (uint)Marshal.ReadInt32(buffer);
            var count = (uint)Marshal.ReadInt32(buffer, 4);
            var stride = Marshal.SizeOf<WlanBssEntry>();
            if (!BssInformationElementReader.IsValidList(totalSize, count))
                throw new WifiException(WifiErrorKind.InvalidNativeData, "Invalid WLAN BSS list size.");
            var accessPoints = new List<WifiAccessPoint>((int)count);
            var observedAt = DateTimeOffset.UtcNow;
            IReadOnlyList<WlanAvailableNetwork>? availableNetworks = null;
            var malformedCount = 0;
            var invalidEntryCount = 0;
            for (var i = 0; i < count; i++)
            {
                var offset = 8 + i * stride;
                var entry = Marshal.PtrToStructure<WlanBssEntry>(buffer + offset);
                if (entry.Ssid.Length > 32) { invalidEntryCount++; continue; }
                var copied = BssInformationElementReader.TryCopy(buffer, totalSize, count, offset, entry, out var elements);
                var capabilities = WifiInformationElementParser.Parse(elements);
                if (!copied || capabilities.HasMalformedElements) malformedCount++;
                WifiSecurityInfo? wep = null;
                if (copied && !capabilities.HasIncompleteSecurityData && !capabilities.HasRsn &&
                    !capabilities.HasWpa && (entry.CapabilityInformation & 0x10) != 0)
                {
                    availableNetworks ??= ReadAvailableNetworks(interfaceId);
                    wep = WepFallbackResolver.Find(entry, availableNetworks);
                }
                var vendor = _vendorResolver.Resolve(new PhysicalAddress(entry.Bssid));
                accessPoints.Add(BssMapper.Map(entry, observedAt, capabilities, vendor, wep, copied));
            }
            if (malformedCount > 0 || invalidEntryCount > 0)
                _logger.Debug("WLAN metadata: {MalformedCount} malformed IE buffers, {InvalidEntryCount} invalid BSS records",
                    malformedCount, invalidEntryCount);
            return accessPoints.AsReadOnly();
        }
        finally { NativeWifiMethods.WlanFreeMemory(buffer); }
    }

    private IReadOnlyList<WlanAvailableNetwork> ReadAvailableNetworks(Guid interfaceId)
    {
        var result = NativeWifiMethods.WlanGetAvailableNetworkList(_handle, interfaceId, 0, IntPtr.Zero, out var buffer);
        try
        {
            if (result != 0 || buffer == IntPtr.Zero)
            {
                _logger.Debug("WLAN WEP corroboration unavailable: {NativeCode}", result);
                return [];
            }
            var count = (uint)Marshal.ReadInt32(buffer);
            if (count > 65536)
            {
                _logger.Debug("Invalid WLAN available-network count; WEP corroboration skipped");
                return [];
            }
            var stride = Marshal.SizeOf<WlanAvailableNetwork>();
            var networks = new List<WlanAvailableNetwork>((int)count);
            for (var i = 0; i < count; i++)
            {
                var network = Marshal.PtrToStructure<WlanAvailableNetwork>(buffer + 8 + i * stride);
                if (network.Ssid.Length <= 32) networks.Add(network);
            }
            return networks.AsReadOnly();
        }
        finally { if (buffer != IntPtr.Zero) NativeWifiMethods.WlanFreeMemory(buffer); }
    }

    private void OnNotification(ref WlanNotificationData data, IntPtr context)
    {
        try
        {
            if ((data.Source & WlanConstants.NotificationSourceAcm) == 0 || !_pending.TryGetValue(data.InterfaceId, out var completion))
                return;
            if (data.Code == WlanConstants.ScanComplete) completion.Complete();
            else if (data.Code == WlanConstants.ScanFail)
            {
                var reason = data.Data != IntPtr.Zero && data.DataSize >= 4 ? (uint)Marshal.ReadInt32(data.Data) : uint.MaxValue;
                completion.Complete(reason == 0 ? uint.MaxValue : reason);
            }
        }
        catch (Exception exception)
        {
            // Never allow a managed exception to cross the unmanaged callback boundary.
            _logger.Error(exception, "WLAN notification callback failed");
            if (_pending.TryGetValue(data.InterfaceId, out var completion)) completion.Fail(exception);
        }
    }

    public void Dispose()
    {
        if (_disposed) return;
        _disposed = true;
        try
        {
            if (_registered)
            {
                var result = NativeWifiMethods.WlanRegisterNotification(_handle, 0, false, null, IntPtr.Zero, IntPtr.Zero, out _);
                if (result != 0) _logger.Warning("WLAN notification unregister failed: {NativeCode}", result);
            }
        }
        finally
        {
            _handle.Dispose();
            GC.KeepAlive(_callback);
        }
    }
}
