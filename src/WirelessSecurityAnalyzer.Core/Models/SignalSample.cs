namespace WirelessSecurityAnalyzer.Core.Models;

public sealed record SignalSample(DateTimeOffset Timestamp, int RssiDbm);
