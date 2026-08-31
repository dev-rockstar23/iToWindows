// Feature: pc-unlock
// PairingResult — typed result returned by PairingHandler.StartPairingAsync.
// Requirements: 6.5, 6.6

namespace PCUnlockService.Pairing;

/// <summary>
/// Discriminated-union result returned by
/// <see cref="IPairingHandler.StartPairingAsync"/>.
/// </summary>
public sealed class PairingResult
{
    // -------------------------------------------------------------------------
    // Discriminator
    // -------------------------------------------------------------------------

    /// <summary>Outcome of the pairing attempt.</summary>
    public PairingOutcome Outcome { get; }

    /// <summary>
    /// The completed <see cref="DeviceRecord"/> when
    /// <see cref="Outcome"/> is <see cref="PairingOutcome.Success"/>;
    /// <c>null</c> otherwise.
    /// </summary>
    public DeviceRecord? Device { get; }

    private PairingResult(PairingOutcome outcome, DeviceRecord? device)
    {
        Outcome = outcome;
        Device  = device;
    }

    // -------------------------------------------------------------------------
    // Factory helpers
    // -------------------------------------------------------------------------

    /// <summary>Creates a successful result carrying the new <see cref="DeviceRecord"/>.</summary>
    public static PairingResult Success(DeviceRecord device)
    {
        ArgumentNullException.ThrowIfNull(device);
        return new PairingResult(PairingOutcome.Success, device);
    }

    /// <summary>Creates a timeout result (no iPhone response within 120 s).</summary>
    public static PairingResult Timeout()
        => new(PairingOutcome.Timeout, null);

    /// <summary>Creates a code-mismatch result (iPhone echoed the wrong Pairing_Code).</summary>
    public static PairingResult CodeMismatch()
        => new(PairingOutcome.CodeMismatch, null);

    /// <summary>Creates a cancelled result (external cancellation token was signalled).</summary>
    public static PairingResult Cancelled()
        => new(PairingOutcome.Cancelled, null);
}

/// <summary>
/// Possible outcomes of a pairing attempt.
/// </summary>
public enum PairingOutcome
{
    /// <summary>Pairing completed; a <see cref="DeviceRecord"/> was committed.</summary>
    Success,

    /// <summary>The iPhone did not respond within 120 seconds (Requirement 6.6).</summary>
    Timeout,

    /// <summary>The iPhone echoed a Pairing_Code that did not match the generated code.</summary>
    CodeMismatch,

    /// <summary>The operation was cancelled via the <see cref="System.Threading.CancellationToken"/>.</summary>
    Cancelled,
}
