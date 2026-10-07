using WirelessSecurityAnalyzer.Core.Models;

namespace WirelessSecurityAnalyzer.Core.Analysis;

/// <summary>A bounded, chronological history belonging to one BSSID.</summary>
public sealed class SignalHistory
{
    private readonly List<SignalSample> _samples = [];
    private readonly object _gate = new();
    public string Bssid { get; }
    public int Capacity { get; }

    public SignalHistory(string bssid, int capacity = 300)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(bssid);
        ArgumentOutOfRangeException.ThrowIfLessThan(capacity, 1);
        Bssid = bssid.Trim().ToUpperInvariant();
        Capacity = capacity;
    }

    public void Add(SignalSample sample)
    {
        ArgumentNullException.ThrowIfNull(sample);
        lock (_gate)
        {
            // Insert after equal timestamps, preserving the order of equal-time measurements.
            var index = _samples.FindLastIndex(s => s.Timestamp <= sample.Timestamp) + 1;
            _samples.Insert(index, sample);
            if (_samples.Count > Capacity) _samples.RemoveAt(0);
        }
    }

    public IReadOnlyList<SignalSample> GetSamples()
    {
        lock (_gate) return Array.AsReadOnly(_samples.ToArray());
    }

    public void Clear()
    {
        lock (_gate) _samples.Clear();
    }
}
