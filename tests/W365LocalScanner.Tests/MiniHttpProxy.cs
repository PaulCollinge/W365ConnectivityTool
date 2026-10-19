using System.Collections.Concurrent;
using System.Net;
using System.Net.Sockets;
using System.Text;

namespace W365LocalScanner.Tests;

internal enum ProxyPolicy
{
    Forward,
    BlockPage200,
    Deny403,
    Blackhole
}

/// <summary>
/// Minimal explicit HTTP proxy for tests: tunnels CONNECT, forwards
/// absolute-URI requests to the real origin, or applies a per-host block
/// policy the way corporate proxies/SWGs do (including the worst case of an
/// HTTP 200 HTML block page, and silent drops).
/// </summary>
internal sealed class MiniHttpProxy : IDisposable
{
    private readonly TcpListener _listener = new(IPAddress.Loopback, 0);
    private readonly Func<string, ProxyPolicy> _policy;
    private readonly CancellationTokenSource _stop = new();
    private readonly ConcurrentBag<TcpClient> _connections = [];

    internal ConcurrentQueue<string> Requests { get; } = new();

    internal int Port => ((IPEndPoint)_listener.LocalEndpoint).Port;

    internal MiniHttpProxy(Func<string, ProxyPolicy> policy)
    {
        _policy = policy;
        _listener.Start();
        _ = AcceptLoopAsync();
    }

    private async Task AcceptLoopAsync()
    {
        while (!_stop.IsCancellationRequested)
        {
            TcpClient client;
            try
            {
                client = await _listener.AcceptTcpClientAsync(_stop.Token);
            }
            catch
            {
                return;
            }
            _connections.Add(client);
            _ = HandleAsync(client);
        }
    }

    private async Task HandleAsync(TcpClient client)
    {
        var token = _stop.Token;
        try
        {
            var stream = client.GetStream();
            var (head, leftover) = await ReadHeadAsync(stream, token);
            var lines = head.Split("\r\n");
            var requestLine = lines[0].Split(' ');
            var method = requestLine[0];
            var target = requestLine[1];

            string host;
            int port;
            Uri? absolute = null;
            if (method == "CONNECT")
            {
                var hostPort = target.Split(':');
                host = hostPort[0];
                port = int.Parse(hostPort[1]);
            }
            else
            {
                absolute = new Uri(target);
                host = absolute.Host;
                port = absolute.Port;
            }

            var policy = _policy(host);
            Requests.Enqueue($"{method} {host}:{port} {policy}");

            switch (policy)
            {
                case ProxyPolicy.Blackhole:
                    await Task.Delay(Timeout.Infinite, token);
                    return;
                case ProxyPolicy.Deny403:
                    await WriteAsync(stream, Response("403 Forbidden", "text/html", "<html>Forbidden by proxy policy</html>", "Via: 1.1 test-proxy\r\n"), token);
                    return;
                case ProxyPolicy.BlockPage200:
                    await WriteAsync(stream, Response("200 OK", "text/html; charset=utf-8",
                        "<html><head><title>Blocked</title></head><body>This URL is blocked by corporate policy.</body></html>", ""), token);
                    return;
            }

            using var upstream = new TcpClient();
            await upstream.ConnectAsync(host, port, token);
            var upstreamStream = upstream.GetStream();

            if (method == "CONNECT")
            {
                await WriteAsync(stream, "HTTP/1.1 200 Connection Established\r\n\r\n", token);
                if (leftover.Length > 0)
                    await upstreamStream.WriteAsync(leftover, token);
                await Task.WhenAny(
                    stream.CopyToAsync(upstreamStream, token),
                    upstreamStream.CopyToAsync(stream, token));
                return;
            }

            int contentLength = 0;
            var forwarded = new StringBuilder($"{method} {absolute!.PathAndQuery} HTTP/1.1\r\n");
            foreach (var line in lines.Skip(1).Where(l => l.Length > 0))
            {
                if (line.StartsWith("Proxy-", StringComparison.OrdinalIgnoreCase)
                    || line.StartsWith("Connection:", StringComparison.OrdinalIgnoreCase))
                    continue;
                if (line.StartsWith("Content-Length:", StringComparison.OrdinalIgnoreCase))
                    contentLength = int.Parse(line["Content-Length:".Length..].Trim());
                forwarded.Append(line).Append("\r\n");
            }
            forwarded.Append("Connection: close\r\n\r\n");

            var body = new byte[contentLength];
            int copied = Math.Min(leftover.Length, contentLength);
            Array.Copy(leftover, body, copied);
            while (copied < contentLength)
            {
                int read = await stream.ReadAsync(body.AsMemory(copied), token);
                if (read == 0)
                    break;
                copied += read;
            }

            await upstreamStream.WriteAsync(Encoding.ASCII.GetBytes(forwarded.ToString()), token);
            await upstreamStream.WriteAsync(body, token);
            await upstreamStream.CopyToAsync(stream, token);
        }
        catch
        {
            // Connection torn down by the client, upstream, or Dispose.
        }
        finally
        {
            client.Dispose();
        }
    }

    private static string Response(string status, string contentType, string body, string extraHeaders) =>
        $"HTTP/1.1 {status}\r\nContent-Type: {contentType}\r\n{extraHeaders}Content-Length: {Encoding.UTF8.GetByteCount(body)}\r\nConnection: close\r\n\r\n{body}";

    private static Task WriteAsync(NetworkStream stream, string text, CancellationToken token) =>
        stream.WriteAsync(Encoding.UTF8.GetBytes(text), token).AsTask();

    private static async Task<(string Head, byte[] Leftover)> ReadHeadAsync(NetworkStream stream, CancellationToken token)
    {
        var buffer = new List<byte>();
        var chunk = new byte[4096];
        while (true)
        {
            int read = await stream.ReadAsync(chunk, token);
            if (read == 0)
                throw new IOException("client closed before sending headers");
            buffer.AddRange(chunk.AsSpan(0, read).ToArray());
            var all = buffer.ToArray();
            int end = IndexOf(all, "\r\n\r\n"u8);
            if (end >= 0)
                return (Encoding.ASCII.GetString(all, 0, end), all[(end + 4)..]);
        }
    }

    private static int IndexOf(byte[] data, ReadOnlySpan<byte> pattern) =>
        data.AsSpan().IndexOf(pattern);

    public void Dispose()
    {
        _stop.Cancel();
        _listener.Stop();
        foreach (var connection in _connections)
            connection.Dispose();
    }
}
