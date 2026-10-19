using System.ComponentModel;
using System.Runtime.InteropServices;

namespace W365LocalScanner;

internal sealed record NativeFetchResult(bool Success, byte[] Body, string? Error);

/// <summary>
/// Fetches a URL with Windows' own certificate retrieval stack (cryptnet),
/// the component the chain engine uses for CRL/OCSP downloads. Unlike a
/// probe on a statically-read proxy setting, this applies whatever proxy
/// discovery Windows itself would use (WinHTTP settings, WPAD/PAC), so it
/// separates "the static route fails" from "Windows cannot reach it".
/// Wire-only retrieval bypasses the local CRL cache, so a cached CRL cannot
/// mask a block.
/// </summary>
internal static class NativeCertificateRetrieval
{
    private const uint CryptWireOnlyRetrieval = 0x00000004;
    private const uint CryptDontCacheResult = 0x00000008;

    [DllImport("cryptnet.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    private static extern bool CryptRetrieveObjectByUrlW(
        string pszUrl,
        IntPtr pszObjectOid,
        uint dwRetrievalFlags,
        uint dwTimeout,
        out IntPtr ppvObject,
        IntPtr hAsyncRetrieve,
        IntPtr pCredentials,
        IntPtr pvVerify,
        IntPtr pAuxInfo);

    [DllImport("crypt32.dll")]
    private static extern void CryptMemFree(IntPtr pv);

    internal static Task<NativeFetchResult> FetchAsync(Uri uri, int timeoutMs) =>
        Task.Run(() => Fetch(uri, timeoutMs));

    private static NativeFetchResult Fetch(Uri uri, int timeoutMs)
    {
        try
        {
            // A null object OID returns the raw encoded bytes as a
            // CRYPT_BLOB_ARRAY, so the same content validation is applied.
            if (!CryptRetrieveObjectByUrlW(
                    uri.AbsoluteUri,
                    IntPtr.Zero,
                    CryptWireOnlyRetrieval | CryptDontCacheResult,
                    (uint)timeoutMs,
                    out var blobArray,
                    IntPtr.Zero,
                    IntPtr.Zero,
                    IntPtr.Zero,
                    IntPtr.Zero))
            {
                return new(false, [], DescribeError(Marshal.GetLastWin32Error()));
            }

            try
            {
                // CRYPT_BLOB_ARRAY { DWORD cBlob; PCRYPT_DATA_BLOB rgBlob; }
                // CRYPT_DATA_BLOB  { DWORD cbData; BYTE* pbData; }
                int count = Marshal.ReadInt32(blobArray);
                if (count == 0)
                    return new(false, [], "no data returned");
                IntPtr blobs = Marshal.ReadIntPtr(blobArray, IntPtr.Size);
                int length = Marshal.ReadInt32(blobs);
                IntPtr data = Marshal.ReadIntPtr(blobs, IntPtr.Size);
                var bytes = new byte[length];
                Marshal.Copy(data, bytes, 0, length);
                return new(true, bytes, null);
            }
            finally
            {
                CryptMemFree(blobArray);
            }
        }
        catch (Exception ex) when (ex is DllNotFoundException or EntryPointNotFoundException)
        {
            return new(false, [], $"Windows certificate retrieval unavailable ({ex.Message})");
        }
    }

    internal static bool IsConnectionFailure(string? error) =>
        error != null && (error.StartsWith("timed out", StringComparison.Ordinal)
            || error.StartsWith("cannot connect", StringComparison.Ordinal)
            || error.StartsWith("connection aborted", StringComparison.Ordinal)
            || error.StartsWith("DNS name not resolved", StringComparison.Ordinal));

    internal static string DescribeError(int error)
    {
        uint code = unchecked((uint)error);
        if ((code & 0xFFFF0000) == 0x80190000)
            return $"HTTP {code & 0xFFFF}";

        uint win32 = (code & 0xFFFF0000) == 0x80070000 ? code & 0xFFFF : code;
        return win32 switch
        {
            12002 => "timed out",
            12007 => "DNS name not resolved",
            12029 => "cannot connect",
            12030 => "connection aborted",
            12152 => "invalid response",
            _ => $"{new Win32Exception(error).Message} (0x{code:X8})"
        };
    }
}
