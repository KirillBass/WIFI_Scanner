using WirelessSecurityAnalyzer.Core.Interfaces;

namespace WirelessSecurityAnalyzer.Core.Analysis.Channels;

/// <summary>
/// Equal-width band intersection approximation: max(0, 1 - center distance / width).
/// This ranks Wi-Fi BSS; it does not simulate an IEEE 802.11 spectral mask.
/// </summary>
public sealed class ChannelOverlapCalculator : IChannelOverlapModel
{
    public double Calculate(double accessPointCenterMhz, double candidateCenterMhz, double widthMhz)
    {
        if (!double.IsFinite(accessPointCenterMhz) || !double.IsFinite(candidateCenterMhz))
            throw new ArgumentException("Channel center frequencies must be finite.");
        if (!double.IsFinite(widthMhz) || widthMhz <= 0)
            throw new ArgumentException("Channel width must be finite and positive.");
        return Math.Clamp(1 - Math.Abs(accessPointCenterMhz - candidateCenterMhz) / widthMhz, 0, 1);
    }
}
