using WirelessSecurityAnalyzer.Core.Models;

namespace WirelessSecurityAnalyzer.Core.Network;

public static class DeviceIdentityMerger
{
    public static DeviceIdentity Merge(DeviceIdentity? previous, DeviceIdentity incoming)
    {
        var old = previous ?? new DeviceIdentity();
        var hostname = Clean(incoming.Hostname);
        var friendly = Clean(incoming.FriendlyName);
        var vendor = Clean(incoming.Vendor);
        var takeHost = hostname is not null && (old.Hostname is null || HostRank(incoming.HostnameSource) >= HostRank(old.HostnameSource));
        var takeFriendly = friendly is not null && (old.FriendlyName is null || FriendlyRank(incoming.FriendlyNameSource) >= FriendlyRank(old.FriendlyNameSource));
        var takeVendor = vendor is not null && (old.Vendor is null || incoming.VendorSource >= old.VendorSource);
        var model = Clean(incoming.ModelName); var description = Clean(incoming.ModelDescription); var type = Clean(incoming.DeviceType);
        var takeMetadata = (model is not null || description is not null || type is not null) && incoming.MetadataSource != DeviceNameSource.None &&
            (old.MetadataSource == DeviceNameSource.None || FriendlyRank(incoming.MetadataSource) >= FriendlyRank(old.MetadataSource));
        static DeviceNameSource Effective(DeviceNameSource field, DeviceNameSource metadata) => field == DeviceNameSource.None ? metadata : field;
        var modelSource = Effective(incoming.ModelNameSource, incoming.MetadataSource);
        var descriptionSource = Effective(incoming.ModelDescriptionSource, incoming.MetadataSource);
        var typeSource = Effective(incoming.DeviceTypeSource, incoming.MetadataSource);
        var takeModel = model is not null && (old.ModelName is null || FriendlyRank(modelSource) >= FriendlyRank(Effective(old.ModelNameSource, old.MetadataSource)));
        var takeDescription = description is not null && (old.ModelDescription is null || FriendlyRank(descriptionSource) >= FriendlyRank(Effective(old.ModelDescriptionSource, old.MetadataSource)));
        var takeType = type is not null && (old.DeviceType is null || FriendlyRank(typeSource) >= FriendlyRank(Effective(old.DeviceTypeSource, old.MetadataSource)));
        var merged = old with
        {
            Hostname = takeHost ? hostname : old.Hostname,
            HostnameSource = takeHost ? incoming.HostnameSource : old.HostnameSource,
            FriendlyName = takeFriendly ? friendly : old.FriendlyName,
            FriendlyNameSource = takeFriendly ? incoming.FriendlyNameSource : old.FriendlyNameSource,
            Vendor = takeVendor ? vendor : old.Vendor,
            VendorSource = takeVendor ? incoming.VendorSource : old.VendorSource,
            ModelName = takeModel ? model : old.ModelName,
            ModelNameSource = takeModel ? modelSource : old.ModelName is null ? DeviceNameSource.None : Effective(old.ModelNameSource, old.MetadataSource),
            ModelDescription = takeDescription ? description : old.ModelDescription,
            ModelDescriptionSource = takeDescription ? descriptionSource : old.ModelDescription is null ? DeviceNameSource.None : Effective(old.ModelDescriptionSource, old.MetadataSource),
            DeviceType = takeType ? type : old.DeviceType,
            DeviceTypeSource = takeType ? typeSource : old.DeviceType is null ? DeviceNameSource.None : Effective(old.DeviceTypeSource, old.MetadataSource),
            MetadataSource = takeMetadata ? incoming.MetadataSource : old.MetadataSource,
            IsPrivateMac = old.IsPrivateMac || incoming.IsPrivateMac
        };
        return merged == old ? old : merged with { LastUpdated = incoming.LastUpdated ?? old.LastUpdated };
    }

    public static string? Clean(string? value)
    {
        if (string.IsNullOrWhiteSpace(value)) return null;
        var trimmed = value.Trim();
        return trimmed.Length is > 0 and <= 512 && !trimmed.Any(char.IsControl) ? trimmed : null;
    }

    private static int HostRank(DeviceNameSource source) => source switch
    { DeviceNameSource.LocalComputer => 5, DeviceNameSource.Mdns => 4, DeviceNameSource.ReverseDns => 3,
      DeviceNameSource.NetBios => 2, DeviceNameSource.Llmnr => 1, _ => 0 };
    private static int FriendlyRank(DeviceNameSource source) => source switch
    { DeviceNameSource.Ssdp => 3, DeviceNameSource.Mdns => 2, _ => 0 };
}
