namespace W365LocalScanner;

internal enum EgressTransitionKind
{
    None,
    PoolAddressObserved,
    Warning
}

internal readonly record struct EgressTransitionDecision(
    EgressTransitionKind Kind,
    string? PreviousAddress,
    string? CurrentAddress,
    int ObservedAddressCount);

internal sealed class EgressTransitionTracker(bool allowPoolRotation)
{
    private readonly HashSet<string> _observedAddresses = new(StringComparer.Ordinal);
    private string? _previousAddress;

    internal EgressTransitionDecision Observe(
        string? currentAddress,
        bool routeChanged,
        bool environmentChanged)
    {
        if (string.IsNullOrWhiteSpace(currentAddress))
            return new(EgressTransitionKind.None, _previousAddress, null, _observedAddresses.Count);

        bool isNewAddress = _observedAddresses.Add(currentAddress);
        string? previousAddress = _previousAddress;
        _previousAddress = currentAddress;

        if (previousAddress == null || previousAddress == currentAddress)
            return new(EgressTransitionKind.None, previousAddress, currentAddress, _observedAddresses.Count);

        if (!allowPoolRotation || routeChanged || environmentChanged)
            return new(EgressTransitionKind.Warning, previousAddress, currentAddress, _observedAddresses.Count);

        return new(
            isNewAddress ? EgressTransitionKind.PoolAddressObserved : EgressTransitionKind.None,
            previousAddress,
            currentAddress,
            _observedAddresses.Count);
    }
}
