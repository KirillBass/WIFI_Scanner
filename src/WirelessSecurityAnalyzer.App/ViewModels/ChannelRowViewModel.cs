using System.Globalization;
using WirelessSecurityAnalyzer.Core.Models;

namespace WirelessSecurityAnalyzer.App.ViewModels;

public sealed record ChannelRowViewModel(ChannelAnalysisResult Result)
{
    private static readonly CultureInfo Russian = CultureInfo.GetCultureInfo("ru-RU");
    public int Channel => Result.Channel;
    public string Frequency => Result.CenterFrequencyMhz.ToString("0.#", Russian) + " МГц";
    public int DirectBssCount => Result.DirectBssCount;
    public int InfluencingBssCount => Result.InfluencingBssCount;
    public double LoadScorePercent => Result.LoadScorePercent;
    public string ScoreText => Result.LoadScorePercent.ToString("0.0", Russian) + "%";
    public bool IsRecommended => Result.IsRecommended;
    public string LevelText => Result.Level switch
    {
        ChannelLoadLevel.Free => "Свободен", ChannelLoadLevel.Low => "Низкая", ChannelLoadLevel.Medium => "Средняя",
        ChannelLoadLevel.High => "Высокая", _ => "Критическая"
    };
}
