using System.Buffers.Binary;
using WirelessSecurityAnalyzer.Core.Models;

namespace WirelessSecurityAnalyzer.Core.Analysis.Wifi;

public static class WifiSecurityDetector
{
    public static WifiSecurityInfo Detect(WifiCapabilities capabilities, bool privacyEnabled,
        WifiSecurityInfo? windowsWep = null, bool informationElementsAvailable = true)
    {
        if (!informationElementsAvailable || capabilities.HasIncompleteSecurityData) return WifiSecurityInfo.Unknown;
        if (capabilities.HasRsn || capabilities.HasWpa) return capabilities.Security;
        if (!privacyEnabled)
            return new()
            {
                Protocol = WifiSecurityProtocol.Open, Authentication = WifiAuthenticationType.Open,
                Source = WifiSecuritySource.BssCapabilities,
                PairwiseCiphers = Array.AsReadOnly(new[] { WifiCipherType.None }), GroupCipher = WifiCipherType.None
            };
        // A privacy bit alone cannot distinguish WEP from missing WPA/RSN metadata.
        return windowsWep is { Protocol: WifiSecurityProtocol.Wep, Source: WifiSecuritySource.WindowsNetworkList }
            ? windowsWep : WifiSecurityInfo.Unknown;
    }

    internal static bool TryParse(ReadOnlySpan<byte> data, bool rsn, out WifiSecurityInfo security)
    {
        security = WifiSecurityInfo.Unknown;
        var reader = new SecurityReader(data);
        if (!reader.TryUInt16(out var version) || version != 1 || !reader.TrySuite(out var group) ||
            !reader.TrySuites(out var pairwise) || !reader.TrySuites(out var akms)) return false;

        ushort? capabilities = null;
        if (reader.Remaining > 0)
        {
            if (!reader.TryUInt16(out var flags)) return false;
            capabilities = flags;
        }
        if (rsn && reader.Remaining > 0)
        {
            if (!reader.TryUInt16(out var pmkidCount) || !reader.TrySkip(pmkidCount * 16)) return false;
            // The optional group management cipher is separate from the group data cipher.
            if (reader.Remaining > 0 && !reader.TrySuite(out _)) return false;
        }
        if (reader.Remaining != 0) return false;
        // MFPR without MFPC is contradictory, so do not label an invalid RSN as WPA3.
        if (rsn && capabilities is { } caps && (caps & 0x0040) != 0 && (caps & 0x0080) == 0) return false;

        var (protocol, authentication, transition) = Classify(akms, rsn);
        security = new()
        {
            Protocol = protocol, Authentication = authentication, IsTransitionMode = transition,
            Source = rsn ? WifiSecuritySource.RsnInformationElement : WifiSecuritySource.WpaInformationElement,
            GroupCipher = Cipher(group, rsn),
            PairwiseCiphers = Array.AsReadOnly(pairwise.Select(suite => Cipher(suite, rsn)).Distinct().ToArray()),
            AkmSuites = Array.AsReadOnly(akms.Distinct().ToArray()),
            ManagementFrameProtectionCapable = rsn && capabilities.HasValue ? (capabilities.Value & 0x0080) != 0 : null,
            ManagementFrameProtectionRequired = rsn && capabilities.HasValue ? (capabilities.Value & 0x0040) != 0 : null
        };
        return true;
    }

    private static (WifiSecurityProtocol, WifiAuthenticationType, bool) Classify(uint[] akms, bool rsn)
    {
        var psk = false;
        var sae = false;
        var eap = false;
        var suiteB192 = false;
        var owe = false;
        var unknown = false;
        var oui = rsn ? 0x000FAC00u : 0x0050F200u;
        foreach (var suite in akms)
        {
            if ((suite & 0xFFFFFF00u) != oui) { unknown = true; continue; }
            switch ((byte)suite)
            {
                case 1: eap = true; break;
                case 2: psk = true; break;
                case 3 or 5 or 14 or 15 or 16 or 17 when rsn: eap = true; break;
                case 4 or 6 or 19 or 20 when rsn: psk = true; break;
                case 8 or 9 or 24 or 25 when rsn: sae = true; break;
                case 12 or 13 when rsn: suiteB192 = true; break;
                case 18 when rsn: owe = true; break;
                default: unknown = true; break;
            }
        }
        var personal = psk || sae;
        var enterprise = eap || suiteB192;
        var auth = !unknown && !owe && personal != enterprise
            ? (personal ? WifiAuthenticationType.Personal : WifiAuthenticationType.Enterprise)
            : WifiAuthenticationType.Unknown;
        var protocol = WifiSecurityProtocol.Unknown;
        if (!rsn) protocol = WifiSecurityProtocol.Wpa;
        else if (!unknown)
        {
            if (owe && !personal && !enterprise) protocol = WifiSecurityProtocol.Owe;
            else if (!owe)
            {
                if (psk && sae) protocol = WifiSecurityProtocol.Wpa2Wpa3Mixed;
                else if (sae && !enterprise || suiteB192 && !eap && !personal) protocol = WifiSecurityProtocol.Wpa3;
                else if (!sae && !suiteB192 && (psk || eap)) protocol = WifiSecurityProtocol.Wpa2;
            }
        }
        return (protocol, auth, protocol == WifiSecurityProtocol.Wpa2Wpa3Mixed);
    }

    private static WifiCipherType Cipher(uint suite, bool rsn)
    {
        if ((suite & 0xFFFFFF00u) != (rsn ? 0x000FAC00u : 0x0050F200u)) return WifiCipherType.Unknown;
        return (byte)suite switch
        {
            // Selector zero in an RSN pairwise list means "use group cipher", not Open.
            1 => WifiCipherType.Wep40, 2 => WifiCipherType.Tkip,
            4 => WifiCipherType.Ccmp, 5 => WifiCipherType.Wep104,
            8 when rsn => WifiCipherType.Gcmp, 9 when rsn => WifiCipherType.Gcmp256,
            10 when rsn => WifiCipherType.Ccmp256, _ => WifiCipherType.Unknown
        };
    }

    private ref struct SecurityReader(ReadOnlySpan<byte> data)
    {
        private ReadOnlySpan<byte> _remaining = data;
        public int Remaining => _remaining.Length;

        public bool TryUInt16(out ushort value)
        {
            value = 0;
            if (_remaining.Length < 2) return false;
            value = BinaryPrimitives.ReadUInt16LittleEndian(_remaining);
            _remaining = _remaining[2..];
            return true;
        }

        public bool TrySuite(out uint suite)
        {
            suite = 0;
            if (_remaining.Length < 4) return false;
            suite = BinaryPrimitives.ReadUInt32BigEndian(_remaining);
            _remaining = _remaining[4..];
            return true;
        }

        public bool TrySuites(out uint[] suites)
        {
            suites = [];
            if (!TryUInt16(out var count) || count == 0 || count > _remaining.Length / 4) return false;
            suites = new uint[count];
            for (var i = 0; i < count; i++)
            {
                TrySuite(out var suite);
                suites[i] = suite;
            }
            return true;
        }

        public bool TrySkip(int length)
        {
            if (length > _remaining.Length) return false;
            _remaining = _remaining[length..];
            return true;
        }
    }
}
