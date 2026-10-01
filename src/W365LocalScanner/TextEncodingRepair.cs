using System.Text;

namespace W365LocalScanner;

internal static class TextEncodingRepair
{
    private static readonly UTF8Encoding StrictUtf8 = new(false, true);

    internal static string Repair(string value)
    {
        if (string.IsNullOrEmpty(value))
            return value;

        var repaired = value;
        for (var pass = 0; pass < 2; pass++)
        {
            var next = RepairOnePass(repaired);
            if (next == repaired)
                break;
            repaired = next;
        }
        return repaired;
    }

    internal static void Repair(TestResult result)
    {
        result.Name = Repair(result.Name);
        result.Description = Repair(result.Description);
        result.ResultValue = Repair(result.ResultValue);
        result.DetailedInfo = Repair(result.DetailedInfo);
        result.RemediationText = Repair(result.RemediationText);
    }

    private static string RepairOnePass(string value)
    {
        StringBuilder? output = null;

        for (var index = 0; index < value.Length;)
        {
            if (!IsMojibakeLead(value[index]) ||
                !TryDecodeSequence(value, index, out var decoded, out var consumed))
            {
                output?.Append(value[index]);
                index++;
                continue;
            }

            output ??= new StringBuilder(value.Length).Append(value, 0, index);
            output.Append(decoded);
            index += consumed;
        }

        return output?.ToString() ?? value;
    }

    private static bool TryDecodeSequence(
        string value,
        int start,
        out string decoded,
        out int consumed)
    {
        Span<byte> bytes = stackalloc byte[4];
        for (var length = Math.Min(4, value.Length - start); length >= 2; length--)
        {
            var encodable = true;
            for (var offset = 0; offset < length; offset++)
            {
                if (!TryGetWindows1252Byte(value[start + offset], out bytes[offset]))
                {
                    encodable = false;
                    break;
                }
            }

            if (!encodable)
                continue;

            try
            {
                var candidate = StrictUtf8.GetString(bytes[..length]);
                if (candidate.Length == 1 && candidate[0] > 0x7f)
                {
                    decoded = candidate;
                    consumed = length;
                    return true;
                }
            }
            catch (DecoderFallbackException)
            {
            }
        }

        decoded = string.Empty;
        consumed = 0;
        return false;
    }

    private static bool IsMojibakeLead(char value) => value is '\u00c2' or '\u00c3' or '\u00e2' or '\u00ef' or '\u00f0';

    private static bool TryGetWindows1252Byte(char value, out byte result)
    {
        if (value <= '\u00ff')
        {
            result = (byte)value;
            return true;
        }

        result = value switch
        {
            '\u20ac' => 0x80,
            '\u201a' => 0x82,
            '\u0192' => 0x83,
            '\u201e' => 0x84,
            '\u2026' => 0x85,
            '\u2020' => 0x86,
            '\u2021' => 0x87,
            '\u02c6' => 0x88,
            '\u2030' => 0x89,
            '\u0160' => 0x8a,
            '\u2039' => 0x8b,
            '\u0152' => 0x8c,
            '\u017d' => 0x8e,
            '\u2018' => 0x91,
            '\u2019' => 0x92,
            '\u201c' => 0x93,
            '\u201d' => 0x94,
            '\u2022' => 0x95,
            '\u2013' => 0x96,
            '\u2014' => 0x97,
            '\u02dc' => 0x98,
            '\u2122' => 0x99,
            '\u0161' => 0x9a,
            '\u203a' => 0x9b,
            '\u0153' => 0x9c,
            '\u017e' => 0x9e,
            '\u0178' => 0x9f,
            _ => 0
        };
        return result != 0;
    }
}

internal sealed class MojibakeRepairingTextWriter(TextWriter inner) : TextWriter
{
    public override Encoding Encoding => inner.Encoding;

    public override void Write(char value) => inner.Write(value);

    public override void Write(string? value) =>
        inner.Write(value is null ? null : TextEncodingRepair.Repair(value));

    public override void WriteLine(string? value) =>
        inner.WriteLine(value is null ? null : TextEncodingRepair.Repair(value));
}
