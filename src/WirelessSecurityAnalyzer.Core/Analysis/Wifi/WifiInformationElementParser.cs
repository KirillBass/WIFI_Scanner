using System.Buffers.Binary;
using System.Numerics;
using WirelessSecurityAnalyzer.Core.Models;

namespace WirelessSecurityAnalyzer.Core.Analysis.Wifi;

/// <summary>Parses only local Beacon/Probe Response metadata. Never retains the input buffer.</summary>
public static class WifiInformationElementParser
{
    public static WifiCapabilities Parse(ReadOnlySpan<byte> elements)
    {
        var ht = false;
        var vht = false;
        var he = false;
        var eht = false;
        var rsn = false;
        var wpa = false;
        var malformed = false;
        var incompleteSecurity = false;
        var rsnSecurity = WifiSecurityInfo.Unknown;
        var wpaSecurity = WifiSecurityInfo.Unknown;
        ReadOnlySpan<byte> firstRsn = default, firstWpa = default, heCapabilities = default;
        // EHT MCS/NSS length depends on HE channel-width support. Resolve after the TLV pass,
        // so the advertised order of HE and EHT elements cannot change detection.
        var ehtCapabilities = new List<byte[]>();
        while (!elements.IsEmpty)
        {
            if (elements.Length < 2 || elements[1] > elements.Length - 2)
            {
                malformed = incompleteSecurity = true;
                break;
            }
            var id = elements[0];
            var value = elements.Slice(2, elements[1]);
            elements = elements[(value.Length + 2)..];
            switch (id)
            {
                case 45: if (value.Length == 26) ht = true; else malformed = true; break;
                case 61: if (value.Length == 22) ht = true; else malformed = true; break;
                case 191: if (value.Length == 12) vht = true; else malformed = true; break;
                case 192: if (value.Length == 5) vht = true; else malformed = true; break;
                case 48:
                    if (rsn && !value.SequenceEqual(firstRsn)) incompleteSecurity = true;
                    if (!rsn) firstRsn = value;
                    rsn = true;
                    if (WifiSecurityDetector.TryParse(value, true, out var parsedRsn)) rsnSecurity = parsedRsn;
                    else malformed = incompleteSecurity = true;
                    break;
                case 221:
                    if (value.Length < 4)
                    {
                        // A partial WPA OUI/type cannot prove that this BSS is open or WEP.
                        if (value.Length < 3 || value[0] == 0 && value[1] == 0x50 && value[2] == 0xf2)
                            malformed = incompleteSecurity = true;
                    }
                    else if (BinaryPrimitives.ReadUInt32BigEndian(value) == 0x0050F201)
                    {
                        if (wpa && !value.SequenceEqual(firstWpa)) incompleteSecurity = true;
                        if (!wpa) firstWpa = value;
                        wpa = true;
                        if (WifiSecurityDetector.TryParse(value[4..], false, out var parsedWpa)) wpaSecurity = parsedWpa;
                        else malformed = incompleteSecurity = true;
                    }
                    break;
                case 255:
                    if (value.IsEmpty) { malformed = true; break; }
                    var extension = value[0];
                    var body = value[1..];
                    switch (extension)
                    {
                        case 35:
                            if (ValidHeCapabilities(body)) { he = true; heCapabilities = body; }
                            else malformed = true;
                            break;
                        case 36: if (ValidHeOperation(body)) he = true; else malformed = true; break;
                        case 106: if (ValidEhtOperation(body)) eht = true; else malformed = true; break;
                        case 108: ehtCapabilities.Add(body.ToArray()); break;
                    }
                    break;
            }
        }
        foreach (var capability in ehtCapabilities)
        {
            if (ValidEhtCapabilities(capability, heCapabilities)) eht = true;
            else malformed = true;
        }
        return new()
        {
            HasHt = ht, HasVht = vht, HasHe = he, HasEht = eht,
            HasRsn = rsn, HasWpa = wpa, HasMalformedElements = malformed,
            HasIncompleteSecurityData = incompleteSecurity,
            Security = incompleteSecurity ? WifiSecurityInfo.Unknown : rsn ? rsnSecurity : wpaSecurity
        };
    }

    private static bool ValidHeCapabilities(ReadOnlySpan<byte> body)
    {
        // Six MAC and eleven PHY octets, then bandwidth-dependent MCS/NSS maps and optional PPE.
        if (body.Length < 21) return false;
        var needed = 21 + ((body[6] & 0x08) != 0 ? 4 : 0) + ((body[6] & 0x10) != 0 ? 4 : 0);
        if (body.Length < needed) return false;
        if ((body[12] & 0x80) != 0)
        {
            if (body.Length <= needed) return false;
            var header = body[needed];
            needed += (7 + 6 * BitOperations.PopCount((uint)(header & 0x78)) * ((header & 7) + 1) + 7) / 8;
        }
        return body.Length >= needed;
    }

    private static bool ValidHeOperation(ReadOnlySpan<byte> body)
    {
        if (body.Length < 6) return false;
        var parameters = BinaryPrimitives.ReadUInt32LittleEndian(body);
        var needed = 6 + ((parameters & 0x4000) != 0 ? 3 : 0) +
            ((parameters & 0x8000) != 0 ? 1 : 0) + ((parameters & 0x20000) != 0 ? 5 : 0);
        return body.Length >= needed;
    }

    private static bool ValidEhtOperation(ReadOnlySpan<byte> body)
    {
        if (body.Length < 5) return false;
        var hasOperation = (body[0] & 1) != 0;
        var hasBitmap = (body[0] & 2) != 0;
        if (hasBitmap && !hasOperation) return false;
        var needed = 5 + (hasOperation ? 3 : 0) + (hasBitmap ? 2 : 0);
        return body.Length >= needed && (!hasOperation || (body[5] & 7) <= 4);
    }

    private static bool ValidEhtCapabilities(ReadOnlySpan<byte> body, ReadOnlySpan<byte> he)
    {
        // In BSS metadata this is an AP capability. Its MCS/NSS field has three octets per width.
        if (body.Length < 14 || he.IsEmpty) return false;
        var widths = he[6];
        var mcsBytes = (widths & 2) != 0 ? 3 :
            ((widths & 4) != 0 ? 3 : 0) + ((widths & 8) != 0 ? 3 : 0) + ((body[2] & 2) != 0 ? 3 : 0);
        var needed = 11 + Math.Max(mcsBytes, 3);
        if (body.Length < needed) return false;
        if ((body[7] & 8) != 0)
        {
            if (body.Length < needed + 2) return false;
            var header = BinaryPrimitives.ReadUInt16LittleEndian(body[needed..]);
            needed += (9 + 6 * BitOperations.PopCount((uint)(header & 0x01F0)) * ((header & 15) + 1) + 7) / 8;
        }
        return body.Length >= needed;
    }
}
