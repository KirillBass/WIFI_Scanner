namespace WirelessSecurityAnalyzer.Core.Interfaces;

public interface IChannelOverlapModel
{
    double Calculate(double accessPointCenterMhz, double candidateCenterMhz, double widthMhz);
}
