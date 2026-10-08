using WirelessSecurityAnalyzer.Core.Common;

namespace WirelessSecurityAnalyzer.Core.Models;

/// <summary>A failed attempt, ordered with successful snapshots; successful BSS data is preserved.</summary>
public sealed record WifiScanFailure(long Version, WifiException Error);
