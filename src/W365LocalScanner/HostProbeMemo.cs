using System.Collections.Concurrent;

namespace W365LocalScanner;

/// <summary>
/// Per-host probe coordination. While a host's state is unknown, probes to
/// it run one at a time; once one succeeds the host runs unrestricted, and
/// once one fails at connection level (timeout / unreachable) later probes
/// to that host reuse that failure instead of waiting out another timeout.
/// </summary>
internal sealed class HostProbeMemo<T>
{
    private readonly ConcurrentDictionary<string, SemaphoreSlim> _gates = new(StringComparer.OrdinalIgnoreCase);
    private readonly ConcurrentDictionary<string, byte> _healthy = new(StringComparer.OrdinalIgnoreCase);
    private readonly ConcurrentDictionary<string, T> _dead = new(StringComparer.OrdinalIgnoreCase);

    internal async Task<T> RunAsync(
        string host,
        Func<Task<T>> probe,
        Func<T, bool> isHealthy,
        Func<T, bool> isConnectionFailure,
        Func<T, T> describeReuse)
    {
        if (_healthy.ContainsKey(host))
            return await probe();

        var gate = _gates.GetOrAdd(host, _ => new SemaphoreSlim(1, 1));
        await gate.WaitAsync();
        bool held = true;
        try
        {
            if (_dead.TryGetValue(host, out var dead))
                return describeReuse(dead);

            if (_healthy.ContainsKey(host))
            {
                gate.Release();
                held = false;
                return await probe();
            }

            var result = await probe();
            if (isHealthy(result))
                _healthy.TryAdd(host, 0);
            else if (isConnectionFailure(result))
                _dead.TryAdd(host, result);
            return result;
        }
        finally
        {
            if (held)
                gate.Release();
        }
    }
}
