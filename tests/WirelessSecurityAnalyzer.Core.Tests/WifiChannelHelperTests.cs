using WirelessSecurityAnalyzer.Core.Analysis;
using WirelessSecurityAnalyzer.Core.Models;

namespace WirelessSecurityAnalyzer.Core.Tests;

public sealed class WifiChannelHelperTests
{
    [Theory]
    [InlineData(2412, WifiBand.Ghz2_4, 1)]
    [InlineData(2437, WifiBand.Ghz2_4, 6)]
    [InlineData(2462, WifiBand.Ghz2_4, 11)]
    [InlineData(2472, WifiBand.Ghz2_4, 13)]
    [InlineData(2484, WifiBand.Ghz2_4, 14)]
    [InlineData(4910, WifiBand.Ghz5, 182)]
    [InlineData(4980, WifiBand.Ghz5, 196)]
    [InlineData(5180, WifiBand.Ghz5, 36)]
    [InlineData(5200, WifiBand.Ghz5, 40)]
    [InlineData(5825, WifiBand.Ghz5, 165)]
    [InlineData(5935, WifiBand.Ghz6, 2)]
    [InlineData(5955, WifiBand.Ghz6, 1)]
    [InlineData(5975, WifiBand.Ghz6, 5)]
    [InlineData(7115, WifiBand.Ghz6, 233)]
    public void RecognizesBandAndChannel(double frequency, WifiBand band, int channel)
    {
        Assert.Equal((band, channel), WifiChannelHelper.FromFrequency(frequency));
    }

    [Theory]
    [InlineData(0)]
    [InlineData(2407)]
    [InlineData(2413)]
    [InlineData(2412.5)]
    [InlineData(2477)]
    [InlineData(2500)]
    [InlineData(5000)]
    [InlineData(5900)]
    [InlineData(5925)]
    [InlineData(5960)]
    [InlineData(7120)]
    [InlineData(double.NaN)]
    [InlineData(double.PositiveInfinity)]
    public void RejectsUnknownOrOffRasterFrequencies(double frequency)
    {
        Assert.Equal((WifiBand.Unknown, 0), WifiChannelHelper.FromFrequency(frequency));
    }

    [Theory]
    [InlineData(WifiBand.Ghz2_4, 1, 2412)]
    [InlineData(WifiBand.Ghz2_4, 14, 2484)]
    [InlineData(WifiBand.Ghz5, 36, 5180)]
    [InlineData(WifiBand.Ghz5, 182, 4910)]
    [InlineData(WifiBand.Ghz6, 1, 5955)]
    [InlineData(WifiBand.Ghz6, 2, 5935)]
    [InlineData(WifiBand.Ghz6, 233, 7115)]
    public void ConvertsBackToFrequency(WifiBand band, int channel, double expected)
    {
        Assert.Equal(expected, WifiChannelHelper.ToFrequency(band, channel));
        Assert.Equal((band, channel), WifiChannelHelper.FromFrequency(expected));
    }

    [Theory]
    [InlineData(WifiBand.Unknown, 1)]
    [InlineData(WifiBand.Ghz2_4, 0)]
    [InlineData(WifiBand.Ghz2_4, 15)]
    [InlineData(WifiBand.Ghz5, 180)]
    [InlineData(WifiBand.Ghz6, 234)]
    public void RejectsInvalidChannel(WifiBand band, int channel) => Assert.Null(WifiChannelHelper.ToFrequency(band, channel));
}
