using Microsoft.VisualStudio.TestTools.UnitTesting;

namespace W365LocalScanner.Tests;

[TestClass]
public sealed class HybridTimeSyncAnalysisTests
{
    [DataTestMethod]
    [DataRow("SI-BCD3003.de.bosch.com")]
    [DataRow("time.windows.com,0x9")]
    [DataRow("VM IC Time Synchronization Provider")]
    public void SynchronizedSourcesAreAccepted(string source)
    {
        Assert.IsTrue(HybridTimeSyncAnalysis.HasSynchronizedSource(source, leapIndicator: 0));
    }

    [DataTestMethod]
    [DataRow(null, 0)]
    [DataRow("", 0)]
    [DataRow("Local CMOS Clock", 0)]
    [DataRow("Free-running System Clock", 0)]
    [DataRow("unknown", 0)]
    [DataRow("ntp.contoso.com", null)]
    [DataRow("ntp.contoso.com", 3)]
    public void UnsynchronizedSourcesAreRejected(string? source, int? leapIndicator)
    {
        Assert.IsFalse(HybridTimeSyncAnalysis.HasSynchronizedSource(source, leapIndicator));
    }
}
