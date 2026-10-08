namespace WirelessSecurityAnalyzer.Infrastructure.Windows.Network.Identity;

public sealed record DeviceIdentityOptions
{
    public TimeSpan QueryTimeout { get; init; } = TimeSpan.FromSeconds(1);
    public TimeSpan MulticastWindow { get; init; } = TimeSpan.FromSeconds(2);
    public TimeSpan CacheTtl { get; init; } = TimeSpan.FromMinutes(15);
    public int MaxConcurrency { get; init; } = 4;
    public int MaxDescriptionBytes { get; init; } = 512 * 1024;
    public int MaxDescriptions { get; init; } = 64;

    public void Validate()
    {
        if (QueryTimeout <= TimeSpan.Zero || QueryTimeout > TimeSpan.FromSeconds(2) ||
            MulticastWindow <= TimeSpan.Zero || MulticastWindow > TimeSpan.FromSeconds(5) ||
            CacheTtl < TimeSpan.FromMinutes(10) || CacheTtl > TimeSpan.FromMinutes(30) ||
            MaxConcurrency is < 1 or > 16 || MaxDescriptionBytes is < 1024 or > 512 * 1024 ||
            MaxDescriptions is < 1 or > 128) throw new ArgumentOutOfRangeException(nameof(DeviceIdentityOptions));
    }
}
