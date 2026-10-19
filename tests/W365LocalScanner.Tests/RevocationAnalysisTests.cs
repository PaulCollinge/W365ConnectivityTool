using System.Formats.Asn1;
using System.Numerics;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using Microsoft.VisualStudio.TestTools.UnitTesting;

namespace W365LocalScanner.Tests;

[TestClass]
public sealed class RevocationAnalysisTests
{
    private static readonly byte[] HtmlBlockPage = Encoding.UTF8.GetBytes(
        "<html><body><h1>Access Denied</h1>This site is blocked by corporate policy.</body></html>");

    [TestMethod]
    public void ExtractsHttpCrlOcspAndIssuerUrlsAndIgnoresLdap()
    {
        using var ca = CreateCertificateAuthority("CN=Test Issuing CA");
        using var leaf = CreateLeaf(ca, "CN=leaf.example",
            crlUrls: ["ldap:///CN=Test,DC=example?certificateRevocationList", "http://crl.example.com/ca.crl"],
            ocspUrls: ["http://ocsp.example.com"],
            caIssuerUrls: ["http://cacerts.example.com/ca.crt"]);

        var urls = RevocationAnalysis.ExtractUrls(leaf);

        CollectionAssert.AreEquivalent(
            new[]
            {
                "Crl http://crl.example.com/ca.crl",
                "Ocsp http://ocsp.example.com/",
                "CaIssuers http://cacerts.example.com/ca.crt"
            },
            urls.Select(u => $"{u.Kind} {u.Uri}").ToArray());
    }

    [TestMethod]
    public void CertificateWithoutRevocationExtensionsYieldsNoUrls()
    {
        using var ca = CreateCertificateAuthority("CN=Root Without Extensions");

        Assert.AreEqual(0, RevocationAnalysis.ExtractUrls(ca).Count);
    }

    [TestMethod]
    public void OcspRequestEncodesRfc6960CertIdForSubjectAndIssuer()
    {
        using var ca = CreateCertificateAuthority("CN=OCSP Issuer");
        using var leaf = CreateLeaf(ca, "CN=ocsp-subject.example");

        var request = RevocationAnalysis.BuildOcspRequest(leaf, ca);

        var certId = new AsnReader(request, AsnEncodingRules.DER)
            .ReadSequence()     // OCSPRequest
            .ReadSequence()     // TBSRequest
            .ReadSequence()     // requestList
            .ReadSequence()     // Request
            .ReadSequence();    // CertID
        var algorithm = certId.ReadSequence();
        Assert.AreEqual("1.3.14.3.2.26", algorithm.ReadObjectIdentifier());
        CollectionAssert.AreEqual(SHA1.HashData(ca.SubjectName.RawData), certId.ReadOctetString());
        CollectionAssert.AreEqual(SHA1.HashData(ca.PublicKey.EncodedKeyValue.RawData), certId.ReadOctetString());
        CollectionAssert.AreEqual(leaf.SerialNumberBytes.ToArray(), certId.ReadIntegerBytes().ToArray());
    }

    [DataTestMethod]
    [DataRow(0, "successful")]
    [DataRow(6, "unauthorized")]
    public void WellFormedOcspResponseIsValid(int responseStatus, string expectedText)
    {
        var body = new byte[] { 0x30, 0x03, 0x0A, 0x01, (byte)responseStatus };

        var result = RevocationAnalysis.ClassifyOcspResponse(200, "application/ocsp-response", body);

        Assert.AreEqual(RevocationProbeOutcome.Valid, result.Outcome);
        StringAssert.Contains(result.Detail, expectedText);
    }

    [TestMethod]
    public void OcspHtmlBlockPageWithHttp200IsBlocked()
    {
        var result = RevocationAnalysis.ClassifyOcspResponse(200, "text/html", HtmlBlockPage);

        Assert.AreEqual(RevocationProbeOutcome.Blocked, result.Outcome);
        StringAssert.Contains(result.Detail, "not an OCSP response");
    }

    [DataTestMethod]
    [DataRow(403, "HTTP 403")]
    [DataRow(407, "requires authentication")]
    [DataRow(502, "HTTP 502")]
    public void NonSuccessStatusIsBlocked(int statusCode, string expectedText)
    {
        var result = RevocationAnalysis.ClassifyOcspResponse(statusCode, "text/html", HtmlBlockPage);

        Assert.AreEqual(RevocationProbeOutcome.Blocked, result.Outcome);
        StringAssert.Contains(result.Detail, expectedText);
    }

    [TestMethod]
    public void RealCrlFromExpectedIssuerIsValid()
    {
        using var ca = CreateCertificateAuthority("CN=CRL Issuer");
        var crl = BuildCrl(ca, revokedCount: 0);

        var result = RevocationAnalysis.ClassifyCrlResponse(200, "application/pkix-crl", crl, ca.SubjectName);

        Assert.AreEqual(RevocationProbeOutcome.Valid, result.Outcome);
        Assert.AreEqual("CRL downloaded", result.Detail);
    }

    [TestMethod]
    public void TruncatedLargeCrlPrefixStillProvesIssuer()
    {
        using var ca = CreateCertificateAuthority("CN=Large CRL Issuer");
        var crl = BuildCrl(ca, revokedCount: 5000);
        Assert.IsTrue(crl.Length > 64 * 1024, "fixture must exceed the scanner's read cap");

        var prefix = crl[..(64 * 1024)];
        var result = RevocationAnalysis.ClassifyCrlResponse(200, "application/pkix-crl", prefix, ca.SubjectName);

        Assert.AreEqual(RevocationProbeOutcome.Valid, result.Outcome);
    }

    [TestMethod]
    public void CrlHtmlBlockPageWithHttp200IsBlocked()
    {
        using var ca = CreateCertificateAuthority("CN=CRL Issuer");

        var result = RevocationAnalysis.ClassifyCrlResponse(200, "text/html", HtmlBlockPage, ca.SubjectName);

        Assert.AreEqual(RevocationProbeOutcome.Blocked, result.Outcome);
        StringAssert.Contains(result.Detail, "not a CRL");
    }

    [TestMethod]
    public void CrlFromDifferentIssuerIsStillReachableButNoted()
    {
        using var ca = CreateCertificateAuthority("CN=Actual CRL Issuer");
        using var other = CreateCertificateAuthority("CN=Expected Issuer");
        var crl = BuildCrl(ca, revokedCount: 0);

        var result = RevocationAnalysis.ClassifyCrlResponse(200, null, crl, other.SubjectName);

        Assert.AreEqual(RevocationProbeOutcome.Valid, result.Outcome);
        StringAssert.Contains(result.Detail, "Actual CRL Issuer");
    }

    [TestMethod]
    public void IssuerCertificateDownloadIsValidatedByContent()
    {
        using var ca = CreateCertificateAuthority("CN=AIA Issuer");

        var valid = RevocationAnalysis.ClassifyIssuerCertificateResponse(200, "application/pkix-cert", ca.RawData, ca.SubjectName);
        var blocked = RevocationAnalysis.ClassifyIssuerCertificateResponse(200, "text/html", HtmlBlockPage, ca.SubjectName);

        Assert.AreEqual(RevocationProbeOutcome.Valid, valid.Outcome);
        Assert.AreEqual(RevocationProbeOutcome.Blocked, blocked.Outcome);
    }

    [TestMethod]
    public void AllRevocationEndpointsReachablePasses()
    {
        var tiers = new[]
        {
            Tier("DigiCert Global Root G2", Probe(RevocationUrlKind.Ocsp, "http://ocsp.digicert.com", RevocationProbeOutcome.Valid),
                Probe(RevocationUrlKind.Crl, "http://crl3.digicert.com/DigiCertGlobalRootG2.crl", RevocationProbeOutcome.Valid))
        };

        var outcome = RevocationAnalysis.Assess(tiers, authoritativeRoute: true);

        Assert.AreEqual("Passed", outcome.Status);
    }

    [TestMethod]
    public void BlockedCrlWithWorkingOcspIsPartialWarning()
    {
        var tiers = new[]
        {
            Tier("Microsoft TLS G2 RSA CA OCSP 10",
                Probe(RevocationUrlKind.Ocsp, "http://oneocsp.microsoft.com/ocsp", RevocationProbeOutcome.Valid),
                Probe(RevocationUrlKind.Crl, "http://crl2.microsoft.com/pkiinfra/CRL/ca.crl", RevocationProbeOutcome.Blocked))
        };

        var outcome = RevocationAnalysis.Assess(tiers, authoritativeRoute: true);

        Assert.AreEqual("Warning", outcome.Status);
        StringAssert.Contains(outcome.Summary, "crl2.microsoft.com");
        StringAssert.Contains(outcome.Summary, "still has one method working on the machine route");
    }

    [TestMethod]
    public void UserContextOnlyMethodDoesNotKeepACaOnlineForSystem()
    {
        // Reviewer scenario: OCSP 407 then cryptnet succeeds as the user; the
        // CRL host is silently dropped. SYSTEM has no verified method.
        var tiers = new[]
        {
            Tier("Microsoft TLS G2 RSA CA OCSP 10",
                Probe(RevocationUrlKind.Ocsp, "http://oneocsp.microsoft.com/ocsp", RevocationProbeOutcome.UserContextOnly),
                Probe(RevocationUrlKind.Crl, "http://crl2.microsoft.com/pkiops/crl/ca.crl", RevocationProbeOutcome.Timeout))
        };

        var outcome = RevocationAnalysis.Assess(tiers, authoritativeRoute: true);

        Assert.AreEqual("Warning", outcome.Status);
        StringAssert.Contains(outcome.Summary, "offline for 1 issuing CA");
        StringAssert.Contains(outcome.Summary, "reachable only in this user's proxy context: oneocsp.microsoft.com");
        StringAssert.Contains(outcome.Remediation!, "oneocsp.microsoft.com worked only with the signed-in user");
    }

    [TestMethod]
    public void BoschScenarioDigiCertBlockedIsOfflineWarningNamingHosts()
    {
        var tiers = new[]
        {
            Tier("DigiCert Global Root G2",
                Probe(RevocationUrlKind.Ocsp, "http://ocsp.digicert.com", RevocationProbeOutcome.Blocked),
                Probe(RevocationUrlKind.Crl, "http://crl3.digicert.com/DigiCertGlobalRootG2.crl", RevocationProbeOutcome.Blocked)),
            Tier("Microsoft TLS RSA Root G2",
                Probe(RevocationUrlKind.Ocsp, "http://oneocsp.microsoft.com/ocsp", RevocationProbeOutcome.Valid))
        };

        var outcome = RevocationAnalysis.Assess(tiers, authoritativeRoute: true);

        Assert.AreEqual("Warning", outcome.Status);
        StringAssert.Contains(outcome.Summary, "offline for 1 issuing CA");
        StringAssert.Contains(outcome.Summary, "crl3.digicert.com, ocsp.digicert.com");
        StringAssert.Contains(outcome.Remediation!, "TCP 80");
        Assert.IsFalse(outcome.Remediation!.Contains("15 seconds"), "fast denies must not be described as stalls");
    }

    [TestMethod]
    public void SilentDropIsCalledOutAsStallRisk()
    {
        var tiers = new[]
        {
            Tier("DigiCert Global Root G2",
                Probe(RevocationUrlKind.Ocsp, "http://ocsp.digicert.com", RevocationProbeOutcome.Timeout),
                Probe(RevocationUrlKind.Crl, "http://crl3.digicert.com/DigiCertGlobalRootG2.crl", RevocationProbeOutcome.Timeout))
        };

        var outcome = RevocationAnalysis.Assess(tiers, authoritativeRoute: true);

        StringAssert.Contains(outcome.Remediation!, "15 seconds");
    }

    [TestMethod]
    public void IssuerDownloadFailureAloneDoesNotWarn()
    {
        var tiers = new[]
        {
            Tier("Microsoft TLS G2 RSA CA OCSP 10",
                Probe(RevocationUrlKind.Ocsp, "http://oneocsp.microsoft.com/ocsp", RevocationProbeOutcome.Valid),
                Probe(RevocationUrlKind.CaIssuers, "http://caissuers.microsoft.com/ca.crt", RevocationProbeOutcome.Blocked))
        };

        Assert.AreEqual("Passed", RevocationAnalysis.Assess(tiers, authoritativeRoute: true).Status);
    }

    [TestMethod]
    public void NonAuthoritativeRouteFailureIsInconclusive()
    {
        var tiers = new[]
        {
            Tier("DigiCert Global Root G2",
                Probe(RevocationUrlKind.Ocsp, "http://ocsp.digicert.com", RevocationProbeOutcome.Blocked))
        };

        var outcome = RevocationAnalysis.Assess(tiers, authoritativeRoute: false);

        Assert.AreEqual("Info", outcome.Status);
        StringAssert.Contains(outcome.Summary, "not a service-route verdict");
    }

    [TestMethod]
    public void NoCollectedChainsIsInfo()
    {
        Assert.AreEqual("Info", RevocationAnalysis.Assess([], authoritativeRoute: true).Status);
    }

    [DataTestMethod]
    [DataRow("http://ocsp.digicert.com")]
    [DataRow("http://ocsp.digicert.com/")]
    public void OcspGetUriAppendsUrlEncodedBase64Once(string responder)
    {
        var request = new byte[] { 0xFB, 0xFF, 0xBF, 0x00 };

        var uri = RevocationAnalysis.BuildOcspGetUri(new Uri(responder), request);

        Assert.AreEqual("http://ocsp.digicert.com/%2B%2F%2B%2FAA%3D%3D", uri.AbsoluteUri);
    }

    [DataTestMethod]
    [DataRow(unchecked((int)0x80190193), "HTTP 403")]
    [DataRow(unchecked((int)0x80072EE2), "timed out")]
    [DataRow(12007, "DNS name not resolved")]
    public void NativeRetrievalErrorsAreDescribed(int error, string expected)
    {
        Assert.AreEqual(expected, NativeCertificateRetrieval.DescribeError(error));
    }

    [TestMethod]
    public void PaddedSerialNumberDoesNotBreakOcspRequest()
    {
        using var ca = CreateCertificateAuthority("CN=Padded Serial Issuer");
        using var leaf = CreateLeaf(ca, "CN=padded.example", serial: [0x00, 0x05, 0x33, 0x44]);

        var request = RevocationAnalysis.BuildOcspRequest(leaf, ca);

        var certId = new AsnReader(request, AsnEncodingRules.DER)
            .ReadSequence().ReadSequence().ReadSequence().ReadSequence().ReadSequence();
        certId.ReadSequence();
        certId.ReadOctetString();
        certId.ReadOctetString();
        CollectionAssert.AreEqual(new byte[] { 0x05, 0x33, 0x44 }, certId.ReadIntegerBytes().ToArray());
    }

    [DataTestMethod]
    [DataRow(new byte[] { 0x00, 0x05 }, new byte[] { 0x05 })]
    [DataRow(new byte[] { 0x00, 0x85 }, new byte[] { 0x00, 0x85 })]
    [DataRow(new byte[] { 0xFF, 0xFF, 0x85 }, new byte[] { 0x85 })]
    [DataRow(new byte[] { 0x00 }, new byte[] { 0x00 })]
    public void MinimalSignedIntegerStripsOnlyRedundantPadding(byte[] input, byte[] expected)
    {
        CollectionAssert.AreEqual(expected, RevocationAnalysis.MinimalSignedInteger(input).ToArray());
    }

    [TestMethod]
    public void HostileCrlLengthsAreRejectedNotThrown()
    {
        var hostile = new byte[] { 0x30, 0x10, 0x30, 0x0E, 0x30, 0x84, 0x7F, 0xFF, 0xFF, 0xF5, 0x30, 0x84, 0x7F, 0xFF, 0xFF, 0xFF, 0x00, 0x00 };

        Assert.IsFalse(RevocationAnalysis.TryReadCrlIssuer(hostile, out _));
        Assert.AreEqual(RevocationProbeOutcome.Blocked,
            RevocationAnalysis.ClassifyCrlResponse(200, null, hostile, new X500DistinguishedName("CN=x")).Outcome);
    }

    [TestMethod]
    public void UserContextOnlyReachabilityIsInfoNotPassOrWarning()
    {
        var tiers = new[]
        {
            Tier("DigiCert Global Root G2",
                Probe(RevocationUrlKind.Ocsp, "http://ocsp.digicert.com", RevocationProbeOutcome.UserContextOnly),
                Probe(RevocationUrlKind.Crl, "http://crl3.digicert.com/DigiCertGlobalRootG2.crl", RevocationProbeOutcome.UserContextOnly)),
            Tier("Microsoft TLS RSA Root G2",
                Probe(RevocationUrlKind.Ocsp, "http://oneocsp.microsoft.com/ocsp", RevocationProbeOutcome.Valid))
        };

        var outcome = RevocationAnalysis.Assess(tiers, authoritativeRoute: true);

        Assert.AreEqual("Info", outcome.Status);
        StringAssert.Contains(outcome.Summary, "crl3.digicert.com, ocsp.digicert.com");
        StringAssert.Contains(outcome.Remediation!, "SYSTEM");
    }

    [TestMethod]
    public void RealFailureStillWarnsWhenOtherHostsAreUserContextOnly()
    {
        var tiers = new[]
        {
            Tier("DigiCert Global Root G2",
                Probe(RevocationUrlKind.Ocsp, "http://ocsp.digicert.com", RevocationProbeOutcome.Blocked),
                Probe(RevocationUrlKind.Crl, "http://crl3.digicert.com/DigiCertGlobalRootG2.crl", RevocationProbeOutcome.Blocked)),
            Tier("Microsoft TLS RSA Root G2",
                Probe(RevocationUrlKind.Ocsp, "http://oneocsp.microsoft.com/ocsp", RevocationProbeOutcome.UserContextOnly))
        };

        var outcome = RevocationAnalysis.Assess(tiers, authoritativeRoute: true);

        Assert.AreEqual("Warning", outcome.Status);
        StringAssert.Contains(outcome.Summary, "(crl3.digicert.com, ocsp.digicert.com)");
        StringAssert.Contains(outcome.Summary, "reachable only in this user's proxy context: oneocsp.microsoft.com");
    }

    private static RevocationTier Tier(string issuer, params (RevocationUrl, RevocationProbeResult)[] probes) =>
        new(issuer, ["example.host"], probes);

    private static (RevocationUrl, RevocationProbeResult) Probe(RevocationUrlKind kind, string url, RevocationProbeOutcome outcome) =>
        (new RevocationUrl(kind, new Uri(url)), new RevocationProbeResult(outcome, outcome.ToString()));

    private static X509Certificate2 CreateCertificateAuthority(string subject)
    {
        using var key = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var request = new CertificateRequest(subject, key, HashAlgorithmName.SHA256);
        request.CertificateExtensions.Add(new X509BasicConstraintsExtension(true, false, 0, true));
        request.CertificateExtensions.Add(new X509KeyUsageExtension(
            X509KeyUsageFlags.KeyCertSign | X509KeyUsageFlags.CrlSign, true));
        request.CertificateExtensions.Add(new X509SubjectKeyIdentifierExtension(request.PublicKey, false));
        return request.CreateSelfSigned(DateTimeOffset.UtcNow.AddDays(-1), DateTimeOffset.UtcNow.AddYears(1));
    }

    private static X509Certificate2 CreateLeaf(
        X509Certificate2 issuer,
        string subject,
        string[]? crlUrls = null,
        string[]? ocspUrls = null,
        string[]? caIssuerUrls = null,
        byte[]? serial = null)
    {
        using var key = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var request = new CertificateRequest(subject, key, HashAlgorithmName.SHA256);
        if (crlUrls != null)
            request.CertificateExtensions.Add(CertificateRevocationListBuilder.BuildCrlDistributionPointExtension(crlUrls));
        if (ocspUrls != null || caIssuerUrls != null)
            request.CertificateExtensions.Add(new X509AuthorityInformationAccessExtension(ocspUrls, caIssuerUrls));
        serial ??= new byte[] { 0x01, 0x23, 0x45, 0x67, 0x89 };
        return request.Create(issuer, DateTimeOffset.UtcNow.AddDays(-1), DateTimeOffset.UtcNow.AddDays(30), serial);
    }

    private static byte[] BuildCrl(X509Certificate2 issuer, int revokedCount)
    {
        var builder = new CertificateRevocationListBuilder();
        for (int i = 0; i < revokedCount; i++)
            builder.AddEntry(new byte[] { 0x7F }.Concat(BitConverter.GetBytes(i + 1)).Concat(new byte[11]).ToArray(), DateTimeOffset.UtcNow.AddDays(-1));
        return builder.Build(issuer, BigInteger.One, DateTimeOffset.UtcNow.AddDays(7), HashAlgorithmName.SHA256);
    }
}
