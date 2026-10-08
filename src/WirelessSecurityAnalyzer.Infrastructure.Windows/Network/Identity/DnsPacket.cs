using System.Buffers.Binary;
using System.Net;
using System.Security.Cryptography;
using System.Text;

namespace WirelessSecurityAnalyzer.Infrastructure.Windows.Network.Identity;

internal sealed record DnsQuestion(string Name, ushort Type);
internal sealed record DnsRecord(string Name, ushort Type, ushort Class, uint Ttl, IPAddress? Address,
    string? Target, ushort Port, IReadOnlyDictionary<string, string> Text, byte[] Raw);
internal sealed record DnsMessage(ushort Id, ushort Flags, IReadOnlyList<DnsQuestion> Questions, IReadOnlyList<DnsRecord> Records)
{
    public bool IsAnswer => (Flags & 0x8000) != 0 && (Flags & 0x000f) == 0 && (Flags & 0x0200) == 0;
}

/// <summary>Shared bounded DNS wire codec for local PTR, mDNS, LLMNR and NBSTAT.</summary>
internal static class DnsPacket
{
    public static ushort NewId() => (ushort)RandomNumberGenerator.GetInt32(1, ushort.MaxValue);
    public static string Reverse(IPAddress address) => string.Join('.', address.GetAddressBytes().Reverse()) + ".in-addr.arpa";

    public static byte[] Query(ushort id, IEnumerable<DnsQuestion> questions, bool recursion = false)
    {
        var list = questions.ToArray();
        using var stream = new MemoryStream();
        U16(stream, id); U16(stream, recursion ? (ushort)0x0100 : (ushort)0);
        U16(stream, checked((ushort)list.Length)); U16(stream, 0); U16(stream, 0); U16(stream, 0);
        foreach (var question in list)
        {
            foreach (var label in question.Name.TrimEnd('.').Split('.'))
            {
                var bytes = Encoding.UTF8.GetBytes(label);
                if (bytes.Length is < 1 or > 63) throw new FormatException("Invalid DNS label.");
                stream.WriteByte((byte)bytes.Length); stream.Write(bytes);
            }
            stream.WriteByte(0); U16(stream, question.Type); U16(stream, 1);
        }
        return stream.ToArray();
    }

    public static DnsMessage Parse(byte[] data, bool netBios = false)
    {
        if (data.Length is < 12 or > 65535) throw new FormatException("Invalid DNS packet size.");
        var offset = 0;
        var id = Read16(data, ref offset); var flags = Read16(data, ref offset);
        var questions = Read16(data, ref offset);
        var count = Read16(data, ref offset) + Read16(data, ref offset) + Read16(data, ref offset);
        if (questions > 1024 || count > 2048) throw new FormatException("Too many DNS records.");
        var names = new List<DnsQuestion>();
        for (var i = 0; i < questions; i++)
        { var name = Name(data, ref offset); var type = Read16(data, ref offset); _ = Read16(data, ref offset); names.Add(new(name, type)); }
        var records = new List<DnsRecord>();
        for (var i = 0; i < count; i++)
        {
            var name = Name(data, ref offset); var type = Read16(data, ref offset); var cls = Read16(data, ref offset);
            Require(data, offset, 4); var ttl = BinaryPrimitives.ReadUInt32BigEndian(data.AsSpan(offset, 4)); offset += 4;
            var length = Read16(data, ref offset); Require(data, offset, length);
            var end = offset + length;
            IPAddress? address = null; string? target = null; ushort port = 0;
            var text = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
            var raw = data.AsSpan(offset, length).ToArray();
            if (type == 1 && length == 4) address = new IPAddress(raw);
            if (type is 12 or 5) target = Name(data, ref offset);
            // NetBIOS NBSTAT and DNS SRV share numeric type 0x21, but have different RDATA.
            if (type == 33 && !netBios)
            {
                if (length < 7) throw new FormatException("Truncated SRV record.");
                offset += 4; port = Read16(data, ref offset); target = Name(data, ref offset);
            }
            if (type == 16)
                while (offset < end)
                {
                    var size = data[offset++];
                    if (offset + size > end) throw new FormatException("Truncated TXT record.");
                    var value = Encoding.UTF8.GetString(data, offset, size); offset += size;
                    var split = value.IndexOf('=');
                    text.TryAdd(split < 0 ? value : value[..split], split < 0 ? "" : value[(split + 1)..]);
                }
            if (offset > end) throw new FormatException("Record exceeds RDATA boundary.");
            offset = end;
            records.Add(new(name, type, (ushort)(cls & 0x7fff), ttl, address, target, port, text, raw));
        }
        return new(id, flags, names.AsReadOnly(), records.AsReadOnly());
    }

    private static string Name(byte[] data, ref int offset)
    {
        var position = offset; var jumped = false; var labels = new List<string>(); var visited = new HashSet<int>(); var total = 0;
        while (true)
        {
            Require(data, position, 1);
            if (!visited.Add(position) || visited.Count > 128) throw new FormatException("DNS compression loop.");
            var length = data[position++];
            if ((length & 0xc0) == 0xc0)
            {
                Require(data, position, 1); var pointer = ((length & 0x3f) << 8) | data[position++];
                if (!jumped) offset = position;
                jumped = true; position = pointer; continue;
            }
            if (length > 63) throw new FormatException("Invalid DNS label encoding.");
            if (length == 0) { if (!jumped) offset = position; return string.Join('.', labels); }
            Require(data, position, length); total += length + 1;
            if (total > 255) throw new FormatException("DNS name too long.");
            var label = Encoding.UTF8.GetString(data, position, length);
            if (label.Any(char.IsControl)) throw new FormatException("Invalid DNS label text.");
            labels.Add(label); position += length;
        }
    }

    private static ushort Read16(byte[] data, ref int offset)
    { Require(data, offset, 2); var value = BinaryPrimitives.ReadUInt16BigEndian(data.AsSpan(offset, 2)); offset += 2; return value; }
    private static void Require(byte[] data, int offset, int length)
    { if (offset < 0 || length < 0 || offset > data.Length - length) throw new FormatException("Truncated DNS packet."); }
    private static void U16(Stream stream, ushort value)
    { Span<byte> bytes = stackalloc byte[2]; BinaryPrimitives.WriteUInt16BigEndian(bytes, value); stream.Write(bytes); }
}
