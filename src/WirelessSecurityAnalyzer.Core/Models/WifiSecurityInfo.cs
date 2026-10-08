namespace WirelessSecurityAnalyzer.Core.Models;

public enum WifiSecurityProtocol { Unknown, Open, Wep, Wpa, Wpa2, Wpa3, Wpa2Wpa3Mixed, Owe }
public enum WifiAuthenticationType { Unknown, Open, Shared, Personal, Enterprise }
public enum WifiCipherType { Unknown, None, Wep40, Wep104, Tkip, Ccmp, Gcmp, Gcmp256, Ccmp256 }
public enum WifiSecuritySource { Unknown, BssCapabilities, WindowsNetworkList, WpaInformationElement, RsnInformationElement }

/// <summary>Advertised BSS security, not the negotiated security of a client connection.</summary>
public sealed record WifiSecurityInfo
{
    public static WifiSecurityInfo Unknown { get; } = new();
    public WifiSecurityProtocol Protocol { get; init; }
    public WifiAuthenticationType Authentication { get; init; }
    public WifiSecuritySource Source { get; init; }
    public IReadOnlyList<WifiCipherType> PairwiseCiphers { get; init; } = Array.Empty<WifiCipherType>();
    public WifiCipherType PairwiseCipher => PairwiseCiphers.Count == 1 ? PairwiseCiphers[0] : WifiCipherType.Unknown;
    public WifiCipherType GroupCipher { get; init; }
    public IReadOnlyList<uint> AkmSuites { get; init; } = Array.Empty<uint>();
    public bool IsEnterprise => Authentication == WifiAuthenticationType.Enterprise;
    public bool IsTransitionMode { get; init; }
    public bool? ManagementFrameProtectionCapable { get; init; }
    public bool? ManagementFrameProtectionRequired { get; init; }
}
