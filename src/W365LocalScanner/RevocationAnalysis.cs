using System.Formats.Asn1;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;

namespace W365LocalScanner;

internal enum RevocationUrlKind
{
    Ocsp,
    Crl,
    CaIssuers
}

internal sealed record RevocationUrl(RevocationUrlKind Kind, Uri Uri);

internal enum RevocationProbeOutcome
{
    Valid,
    Blocked,
    Timeout,
    Unreachable
}

internal sealed record RevocationProbeResult(RevocationProbeOutcome Outcome, string Detail);

/// <summary>
/// One issuing CA's revocation endpoints, plus the probe results for each.
/// "Issuer" is the CA whose OCSP responder / CRL Windows must reach to check
/// certificates it issued; <see cref="UsedBy"/> lists the endpoints whose
/// certificate chains contain such a certificate.
/// </summary>
internal sealed record RevocationTier(
    string IssuerName,
    IReadOnlyList<string> UsedBy,
    IReadOnlyList<(RevocationUrl Url, RevocationProbeResult Result)> Probes);

internal static class RevocationAnalysis
{
    private const string CrlDistributionPointsOid = "2.5.29.31";
    private const string AuthorityInfoAccessOid = "1.3.6.1.5.5.7.1.1";
    private const string OcspAccessMethodOid = "1.3.6.1.5.5.7.48.1";
    private const string CaIssuersAccessMethodOid = "1.3.6.1.5.5.7.48.2";
    private const string Sha1Oid = "1.3.14.3.2.26";

    private static readonly Asn1Tag Context0 = new(TagClass.ContextSpecific, 0, isConstructed: true);
    private static readonly Asn1Tag UriGeneralName = new(TagClass.ContextSpecific, 6);

    /// <summary>
    /// HTTP(S) revocation and issuer URLs that Windows' chain engine would
    /// fetch to validate <paramref name="certificate"/>. LDAP and other
    /// schemes are ignored because they are not used for these public CAs.
    /// </summary>
    internal static IReadOnlyList<RevocationUrl> ExtractUrls(X509Certificate2 certificate)
    {
        var urls = new List<RevocationUrl>();
        foreach (var extension in certificate.Extensions)
        {
            try
            {
                if (extension.Oid?.Value == CrlDistributionPointsOid)
                    urls.AddRange(ParseCrlDistributionPoints(extension.RawData));
                else if (extension.Oid?.Value == AuthorityInfoAccessOid)
                    urls.AddRange(ParseAuthorityInfoAccess(extension.RawData));
            }
            catch (AsnContentException)
            {
                // A malformed extension cannot be fetched by Windows either.
            }
        }
        return urls.Distinct().ToList();
    }

    internal static IEnumerable<RevocationUrl> ParseCrlDistributionPoints(byte[] rawData)
    {
        var results = new List<RevocationUrl>();
        var points = new AsnReader(rawData, AsnEncodingRules.DER).ReadSequence();
        while (points.HasData)
        {
            var point = points.ReadSequence();
            if (!point.HasData || !point.PeekTag().HasSameClassAndValue(Context0))
                continue;

            // distributionPoint [0] is a CHOICE, so its tag is explicit; the
            // fullName [0] alternative is an implicitly-tagged GeneralNames.
            var pointName = point.ReadSequence(Context0);
            if (!pointName.HasData || !pointName.PeekTag().HasSameClassAndValue(Context0))
                continue;

            var names = pointName.ReadSequence(Context0);
            while (names.HasData)
            {
                if (TryReadUriGeneralName(names, out var uri))
                    results.Add(new(RevocationUrlKind.Crl, uri));
            }
        }
        return results;
    }

    internal static IEnumerable<RevocationUrl> ParseAuthorityInfoAccess(byte[] rawData)
    {
        var results = new List<RevocationUrl>();
        var descriptions = new AsnReader(rawData, AsnEncodingRules.DER).ReadSequence();
        while (descriptions.HasData)
        {
            var description = descriptions.ReadSequence();
            var method = description.ReadObjectIdentifier();
            if (!description.HasData || !TryReadUriGeneralName(description, out var uri))
                continue;

            if (method == OcspAccessMethodOid)
                results.Add(new(RevocationUrlKind.Ocsp, uri));
            else if (method == CaIssuersAccessMethodOid)
                results.Add(new(RevocationUrlKind.CaIssuers, uri));
        }
        return results;
    }

    private static bool TryReadUriGeneralName(AsnReader reader, out Uri uri)
    {
        uri = null!;
        if (!reader.PeekTag().HasSameClassAndValue(UriGeneralName))
        {
            reader.ReadEncodedValue();
            return false;
        }

        var value = reader.ReadCharacterString(UniversalTagNumber.IA5String, UriGeneralName);
        if (!Uri.TryCreate(value, UriKind.Absolute, out var parsed)
            || (parsed.Scheme != Uri.UriSchemeHttp && parsed.Scheme != Uri.UriSchemeHttps))
            return false;

        uri = parsed;
        return true;
    }

    /// <summary>
    /// Builds a single-certificate RFC 6960 OCSP request (SHA-1 CertID, the
    /// form every public responder accepts). Sending a real request is the
    /// only way to prove the responder itself answered — a proxy block page
    /// cannot produce a well-formed OCSPResponse.
    /// </summary>
    internal static byte[] BuildOcspRequest(X509Certificate2 subject, X509Certificate2 issuer)
    {
        byte[] issuerNameHash = SHA1.HashData(issuer.SubjectName.RawData);
        byte[] issuerKeyHash = SHA1.HashData(issuer.PublicKey.EncodedKeyValue.RawData);

        var writer = new AsnWriter(AsnEncodingRules.DER);
        using (writer.PushSequence())           // OCSPRequest
        using (writer.PushSequence())           // TBSRequest
        using (writer.PushSequence())           // requestList
        using (writer.PushSequence())           // Request
        using (writer.PushSequence())           // CertID
        {
            using (writer.PushSequence())
            {
                writer.WriteObjectIdentifier(Sha1Oid);
                writer.WriteNull();
            }
            writer.WriteOctetString(issuerNameHash);
            writer.WriteOctetString(issuerKeyHash);
            writer.WriteInteger(subject.SerialNumberBytes.Span);
        }
        return writer.Encode();
    }

    internal static RevocationProbeResult ClassifyOcspResponse(int statusCode, string? contentType, byte[] body)
    {
        if (statusCode != 200)
            return Blocked(statusCode, contentType, "OCSP responder");

        if (!TryReadOcspResponseStatus(body, out int responseStatus))
            return new(RevocationProbeOutcome.Blocked,
                $"HTTP 200 but the body is not an OCSP response ({DescribeContent(contentType, body)}) — typically a proxy/SWG block or warning page");

        return new(RevocationProbeOutcome.Valid, responseStatus == 0
            ? "OCSP responder answered (successful)"
            : $"OCSP responder answered (responseStatus {DescribeOcspStatus(responseStatus)})");
    }

    internal static bool TryReadOcspResponseStatus(byte[] body, out int responseStatus)
    {
        responseStatus = -1;
        try
        {
            var response = new AsnReader(body, AsnEncodingRules.BER).ReadSequence();
            var status = response.ReadEnumeratedBytes().Span;
            if (status.Length != 1)
                return false;
            responseStatus = status[0];
            return responseStatus is >= 0 and <= 6 and not 4;
        }
        catch (AsnContentException)
        {
            return false;
        }
    }

    private static string DescribeOcspStatus(int status) => status switch
    {
        1 => "malformedRequest",
        2 => "internalError",
        3 => "tryLater",
        5 => "sigRequired",
        6 => "unauthorized",
        _ => status.ToString()
    };

    /// <summary>
    /// Classifies a CRL download. Only a prefix of the body is needed: the
    /// issuer Name sits at the start of TBSCertList, so a capped read proves
    /// the CA's CRL (not a block page) was served without downloading it all.
    /// </summary>
    internal static RevocationProbeResult ClassifyCrlResponse(
        int statusCode,
        string? contentType,
        byte[] bodyPrefix,
        X500DistinguishedName expectedIssuer)
    {
        if (statusCode != 200)
            return Blocked(statusCode, contentType, "CRL server");

        if (!TryReadCrlIssuer(bodyPrefix, out var issuer))
            return new(RevocationProbeOutcome.Blocked,
                $"HTTP 200 but the body is not a CRL ({DescribeContent(contentType, bodyPrefix)}) — typically a proxy/SWG block or warning page");

        return SameName(issuer, expectedIssuer)
            ? new(RevocationProbeOutcome.Valid, "CRL downloaded")
            : new(RevocationProbeOutcome.Valid, $"CRL downloaded (issued by '{issuer.Name}')");
    }

    internal static bool TryReadCrlIssuer(ReadOnlySpan<byte> data, out X500DistinguishedName issuer)
    {
        issuer = null!;
        // CertificateList ::= SEQUENCE { tbsCertList SEQUENCE { version INTEGER OPTIONAL,
        //   signature AlgorithmIdentifier, issuer Name, ... }, ... }
        if (!TryReadHeader(data, 0, 0x30, out int certListContent, out _))
            return false;
        if (!TryReadHeader(data, certListContent, 0x30, out int position, out _))
            return false;

        if (position < data.Length && data[position] == 0x02)
        {
            if (!TryReadHeader(data, position, 0x02, out int versionContent, out int versionLength))
                return false;
            position = versionContent + versionLength;
        }

        if (!TryReadHeader(data, position, 0x30, out int algorithmContent, out int algorithmLength))
            return false;
        position = algorithmContent + algorithmLength;

        if (!TryReadHeader(data, position, 0x30, out int issuerContent, out int issuerLength)
            || issuerContent + issuerLength > data.Length)
            return false;

        try
        {
            issuer = new X500DistinguishedName(data[position..(issuerContent + issuerLength)].ToArray());
            return true;
        }
        catch (CryptographicException)
        {
            return false;
        }
    }

    private static bool TryReadHeader(
        ReadOnlySpan<byte> data,
        int offset,
        byte expectedTag,
        out int contentOffset,
        out int length)
    {
        contentOffset = 0;
        length = 0;
        if (offset < 0 || offset + 2 > data.Length || data[offset] != expectedTag)
            return false;

        int position = offset + 1;
        byte first = data[position++];
        if (first < 0x80)
        {
            length = first;
        }
        else
        {
            int count = first & 0x7F;
            if (count is 0 or > 4 || position + count > data.Length)
                return false;
            long value = 0;
            for (int i = 0; i < count; i++)
                value = (value << 8) | data[position++];
            if (value > int.MaxValue)
                return false;
            length = (int)value;
        }

        contentOffset = position;
        return true;
    }

    internal static RevocationProbeResult ClassifyIssuerCertificateResponse(
        int statusCode,
        string? contentType,
        byte[] body,
        X500DistinguishedName expectedSubject)
    {
        if (statusCode != 200)
            return Blocked(statusCode, contentType, "issuer-certificate server");

        var certificates = new X509Certificate2Collection();
        try
        {
            certificates.Import(body);
        }
        catch (CryptographicException)
        {
            return new(RevocationProbeOutcome.Blocked,
                $"HTTP 200 but the body is not a certificate ({DescribeContent(contentType, body)}) — typically a proxy/SWG block or warning page");
        }

        try
        {
            if (certificates.Count == 0)
                return new(RevocationProbeOutcome.Blocked, "HTTP 200 but no certificate was returned");
            return certificates.Any(c => SameName(c.SubjectName, expectedSubject))
                ? new(RevocationProbeOutcome.Valid, "issuer certificate downloaded")
                : new(RevocationProbeOutcome.Valid, "certificate downloaded (subject differs from the expected issuer)");
        }
        finally
        {
            foreach (var certificate in certificates)
                certificate.Dispose();
        }
    }

    private static RevocationProbeResult Blocked(int statusCode, string? contentType, string server) =>
        statusCode == 407
            ? new(RevocationProbeOutcome.Blocked,
                "HTTP 407 — the proxy requires authentication; SYSTEM-context certificate downloads cannot answer an interactive proxy challenge")
            : new(RevocationProbeOutcome.Blocked,
                $"HTTP {statusCode} ({DescribeContent(contentType, null)}) — the {server} did not serve revocation data on this route");

    private static string DescribeContent(string? contentType, byte[]? body)
    {
        var type = string.IsNullOrWhiteSpace(contentType) ? "no content-type" : contentType;
        return body == null ? type : $"{type}, {body.Length} bytes";
    }

    private static bool SameName(X500DistinguishedName left, X500DistinguishedName right) =>
        left.RawData.AsSpan().SequenceEqual(right.RawData)
        || string.Equals(left.Name, right.Name, StringComparison.OrdinalIgnoreCase);

    /// <summary>
    /// Turns per-URL probe results into a test verdict. Windows checks a
    /// certificate's revocation via OCSP first and falls back to the CRL, so
    /// a tier is only "offline" when neither works. AIA issuer downloads are
    /// reported but do not affect the verdict: they are only fetched when a
    /// server omits an intermediate, which none of the sampled endpoints do.
    /// Never returns Failed — Windows components that use these chains
    /// overwhelmingly treat "revocation offline" as a soft failure, so the
    /// honest classification is a Warning with the concrete impact.
    /// </summary>
    internal static DiagnosticOutcome Assess(IReadOnlyList<RevocationTier> tiers, bool authoritativeRoute)
    {
        var checkedTiers = tiers
            .Where(t => t.Probes.Any(p => p.Url.Kind != RevocationUrlKind.CaIssuers))
            .ToList();
        if (checkedTiers.Count == 0)
        {
            return new("Info",
                "No certificate chains could be collected, so revocation endpoints were not tested",
                "Re-run once C-EP-02 shows the HTTPS endpoints are reachable.");
        }

        static bool IsRevocation((RevocationUrl Url, RevocationProbeResult Result) p) =>
            p.Url.Kind != RevocationUrlKind.CaIssuers;

        var offline = checkedTiers
            .Where(t => !t.Probes.Where(IsRevocation).Any(p => p.Result.Outcome == RevocationProbeOutcome.Valid))
            .ToList();
        var failedHosts = checkedTiers
            .SelectMany(t => t.Probes.Where(IsRevocation))
            .Where(p => p.Result.Outcome != RevocationProbeOutcome.Valid)
            .Select(p => p.Url.Uri.Host)
            .Distinct(StringComparer.OrdinalIgnoreCase)
            .OrderBy(h => h, StringComparer.OrdinalIgnoreCase)
            .ToList();
        bool anyTimeout = checkedTiers
            .SelectMany(t => t.Probes.Where(IsRevocation))
            .Any(p => p.Result.Outcome == RevocationProbeOutcome.Timeout);

        if (failedHosts.Count == 0)
        {
            return new("Passed",
                $"All revocation endpoints reachable for {checkedTiers.Count} issuing CA(s) in the sampled certificate chains");
        }

        var hostList = string.Join(", ", failedHosts);
        var remediation =
            $"Allow outbound HTTP (TCP 80) from session hosts to: {hostList}. These hosts are derived from the certificates the AVD and Arc endpoints actually present; " +
            "the AVD list documents *.digicert.com:80 as optional, but Windows uses these hosts to check revocation of every Microsoft TLS chain sampled.";
        if (anyTimeout)
            remediation += " At least one request timed out instead of being refused: Windows waits up to 15 seconds per unreachable revocation URL, which can stall TLS connections. A fast deny is far less disruptive than a silent drop.";

        if (!authoritativeRoute)
        {
            return new("Info",
                $"Revocation endpoint(s) unreachable on the invoking-user route ({hostList}); machine WinHTTP route unavailable, so this is not a service-route verdict",
                remediation);
        }

        if (offline.Count > 0)
        {
            return new("Warning",
                $"Certificate revocation offline for {offline.Count} issuing CA(s) — neither OCSP nor CRL reachable ({hostList})",
                remediation);
        }

        return new("Warning",
            $"{failedHosts.Count} revocation host(s) unreachable ({hostList}); every issuing CA still has one working method",
            remediation);
    }
}
