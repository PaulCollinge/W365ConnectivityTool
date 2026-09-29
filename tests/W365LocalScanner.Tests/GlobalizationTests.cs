using System.Text;
using System.Text.Json;
using Microsoft.VisualStudio.TestTools.UnitTesting;

namespace W365LocalScanner.Tests;

[TestClass]
public sealed class GlobalizationTests
{
    private const string Arabic =
        "أنا اختبار إدخال النص في لغات مختلفة 01 لأحد منتجات Microsoft";

    private const string WorldScripts =
        "中文 日本語 한국어 हिन्दी עברית";

    private const string SupplementaryAndCombining =
        "Emoji 😀 𠀋 👩🏽‍💻; combining e\u0301";

    [TestMethod]
    public async Task ScanJsonRoundTripsUnicodeThroughUtf8File()
    {
        var output = new ScanOutput
        {
            Timestamp = DateTime.UtcNow,
            ScannerVersion = "test",
            MachineName = $"جهاز-{WorldScripts}-{SupplementaryAndCombining}",
            OsVersion = WorldScripts,
            DotNetVersion = ".NET 8",
            Results =
            [
                new TestResult
                {
                    Id = "globalization",
                    Name = WorldScripts,
                    Description = Arabic,
                    Category = "local",
                    Status = "Passed",
                    ResultValue = SupplementaryAndCombining,
                    DetailedInfo = $"{Arabic}\n{WorldScripts}\n{SupplementaryAndCombining}"
                }
            ]
        };

        var json = JsonSerializer.Serialize(output, ScanJsonContext.Default.ScanOutput);
        var path = Path.Combine(Path.GetTempPath(), $"w365-globalization-{Guid.NewGuid():N}.json");

        try
        {
            await File.WriteAllTextAsync(path, json, Encoding.UTF8);

            var bytes = await File.ReadAllBytesAsync(path);
            var preamble = Encoding.UTF8.GetPreamble();
            var hasPreamble = bytes.Length >= preamble.Length;
            for (var i = 0; hasPreamble && i < preamble.Length; i++)
            {
                hasPreamble = bytes[i] == preamble[i];
            }
            var payloadOffset = hasPreamble ? preamble.Length : 0;

            var decoded = new UTF8Encoding(
                encoderShouldEmitUTF8Identifier: false,
                throwOnInvalidBytes: true).GetString(bytes, payloadOffset, bytes.Length - payloadOffset);
            var roundTrip = JsonSerializer.Deserialize(decoded, ScanJsonContext.Default.ScanOutput);

            Assert.IsNotNull(roundTrip);
            Assert.AreEqual(output.MachineName, roundTrip.MachineName);
            Assert.AreEqual(WorldScripts, roundTrip.OsVersion);
            Assert.AreEqual(Arabic, roundTrip.Results[0].Description);
            Assert.AreEqual(SupplementaryAndCombining, roundTrip.Results[0].ResultValue);
            Assert.AreEqual(output.Results[0].DetailedInfo, roundTrip.Results[0].DetailedInfo);
        }
        finally
        {
            if (File.Exists(path))
            {
                File.Delete(path);
            }
        }
    }
}
