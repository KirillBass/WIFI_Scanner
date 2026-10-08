using WirelessSecurityAnalyzer.Core.Models;
using WirelessSecurityAnalyzer.Core.Network;

namespace WirelessSecurityAnalyzer.Infrastructure.Windows.Network.Identity;

public sealed class MacVendorResolver
{
    private readonly Lazy<IReadOnlyDictionary<string, string>> _vendors = new(Load);

    public DeviceIdentity Resolve(NetworkDevice device)
    {
        var privateMac = MacAddressHelper.IsLocallyAdministered(device.MacAddress);
        if (privateMac || !DeviceStateTracker.ValidMac(device.MacAddress)) return new() { IsPrivateMac = privateMac };
        var mac = device.MacAddress!.ToString();
        foreach (var length in new[] { 9, 7, 6 })
            if (_vendors.Value.TryGetValue(mac[..length], out var vendor))
                return new() { Vendor = vendor, VendorSource = DeviceVendorSource.Oui };
        return new();
    }

    private static IReadOnlyDictionary<string, string> Load()
    {
        using var stream = typeof(MacVendorResolver).Assembly.GetManifestResourceStream("WirelessSecurityAnalyzer.Oui.tsv")
            ?? throw new InvalidOperationException("The embedded IEEE OUI database is missing.");
        using var reader = new StreamReader(stream);
        var result = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
        while (reader.ReadLine() is { } line)
        {
            var split = line.IndexOf('\t');
            if (split > 0) result[line[..split]] = line[(split + 1)..];
        }
        return result;
    }
}
