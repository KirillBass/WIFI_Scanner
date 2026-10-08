namespace WirelessSecurityAnalyzer.Core.Models;

public enum DeviceNameSource { None, LocalComputer, ReverseDns, Mdns, NetBios, Llmnr, Ssdp }
public enum DeviceVendorSource { None, Oui, Ssdp }
public enum IdentificationConfidence { Unknown, Low, Medium, High }

/// <summary>Names are separate facts; a vendor never implies a model or device type.</summary>
public sealed record DeviceIdentity
{
    public string? Hostname { get; init; }
    public string? FriendlyName { get; init; }
    public string? Vendor { get; init; }
    public string? ModelName { get; init; }
    public string? ModelDescription { get; init; }
    public string? DeviceType { get; init; }
    public DeviceNameSource HostnameSource { get; init; }
    public DeviceNameSource FriendlyNameSource { get; init; }
    public DeviceNameSource MetadataSource { get; init; }
    public DeviceNameSource ModelNameSource { get; init; }
    public DeviceNameSource ModelDescriptionSource { get; init; }
    public DeviceNameSource DeviceTypeSource { get; init; }
    public DeviceVendorSource VendorSource { get; init; }
    public bool IsPrivateMac { get; init; }
    public DateTimeOffset? LastUpdated { get; init; }
    public DeviceNameSource NameSource => !string.IsNullOrWhiteSpace(FriendlyName) ? FriendlyNameSource :
        !string.IsNullOrWhiteSpace(Hostname) ? HostnameSource : DeviceNameSource.None;
    public string DisplayName => !string.IsNullOrWhiteSpace(FriendlyName) ? FriendlyName : !string.IsNullOrWhiteSpace(Hostname) ? Hostname : "—";
    public IdentificationConfidence Confidence => NameSource is DeviceNameSource.LocalComputer or DeviceNameSource.Ssdp
        ? IdentificationConfidence.High : NameSource != DeviceNameSource.None ? IdentificationConfidence.Medium :
        Vendor is not null ? IdentificationConfidence.Low : IdentificationConfidence.Unknown;
}
