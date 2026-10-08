namespace WirelessSecurityAnalyzer.Core.Models;

public sealed record ChannelAnalysisResult(WifiBand Band, int Channel, double CenterFrequencyMhz,
    int DirectBssCount, int InfluencingBssCount, double RawScore, double LoadScorePercent,
    ChannelLoadLevel Level, bool IsRecommended, bool UsesEstimatedWidth);
