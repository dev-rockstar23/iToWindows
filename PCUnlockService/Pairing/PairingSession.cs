// Feature: pc-unlock
// PairingSession — transient, in-memory state for an active pairing attempt.
// Requirements: 6.5, 6.6

namespace PCUnlockService.Pairing;

/// <summary>
/// The lifecycle state of a pairing session.
/// </summary>
public enum PairingSessionState
{
    /// <summary>QR code has been generated; waiting for the iPhone to scan it.</summary>
    PendingScan,

    /// <summary>iPhone scanned the QR code; waiting for the user to confirm the Pairing_Code on both devices.</summary>
    PendingConfirmation,

    /// <summary>Both sides confirmed; pairing completed successfully.</summary>
    Complete,

    /// <summary>Session was cancelled (timeout, mismatch, or explicit cancellation).</summary>
    Cancelled,
}

/// <summary>
/// Transient in-memory state for a single pairing attempt.
/// </summary>
/// <remarks>
/// This object is never persisted.  All fields are discarded when the session
/// ends (success, timeout, or mismatch).  The <see cref="DeviceRecord"/> that
/// results from a successful pairing is persisted separately.
/// </remarks>
public sealed class PairingSession
{
    /// <summary>Unique identifier for this pairing session.</summary>
    public Guid SessionId { get; init; } = Guid.NewGuid();

    /// <summary>6-character alphanumeric uppercase Pairing_Code displayed on both devices.</summary>
    public string PairingCode { get; init; } = string.Empty;

    /// <summary>128-bit (16-byte) PC identity token generated at session start.</summary>
    public byte[] PcIdentityToken { get; init; } = Array.Empty<byte>();

    /// <summary>When this session was created (UTC).</summary>
    public DateTimeOffset CreatedAt { get; init; }

    /// <summary>When this session expires — <see cref="CreatedAt"/> + 120 seconds (Requirement 6.6).</summary>
    public DateTimeOffset ExpiresAt { get; init; }

    /// <summary>Current lifecycle state of the session.</summary>
    public PairingSessionState State { get; set; } = PairingSessionState.PendingScan;

    /// <summary>
    /// Public key bytes received from the iPhone (SPKI DER) before they have
    /// been committed to the Device Registry.  <c>null</c> until the iPhone
    /// sends its <see cref="PairingRequest"/>.
    /// </summary>
    public byte[]? PendingPublicKey { get; set; }

    /// <summary>Returns <c>true</c> if the session has not yet expired.</summary>
    public bool IsAlive(DateTimeOffset now) => now < ExpiresAt;

    /// <summary>Returns <c>true</c> if the session has expired (wall-clock UTC).</summary>
    public bool IsExpired => DateTimeOffset.UtcNow >= ExpiresAt;

    /// <summary>
    /// Zeroes and clears all sensitive in-memory fields:
    /// <see cref="PendingPublicKey"/> and the internal copy of
    /// <see cref="PcIdentityToken"/>.
    /// Call this on timeout, mismatch, or cancellation before discarding
    /// the session object.
    /// </summary>
    public void ClearSensitiveData()
    {
        if (PendingPublicKey is not null)
        {
            Array.Clear(PendingPublicKey, 0, PendingPublicKey.Length);
            PendingPublicKey = null;
        }

        // PcIdentityToken is init-only on the record, but we zero the array
        // contents so the bytes do not linger in the managed heap.
        if (PcIdentityToken.Length > 0)
        {
            Array.Clear(PcIdentityToken, 0, PcIdentityToken.Length);
        }
    }

    /// <summary>
    /// Factory method — creates a fresh session initialised to
    /// <see cref="PairingSessionState.PendingScan"/>.
    /// </summary>
    public static PairingSession Create(
        string pairingCode,
        byte[] pcIdentityToken,
        DateTimeOffset createdAt)
    {
        return new PairingSession
        {
            SessionId      = Guid.NewGuid(),
            PairingCode    = pairingCode,
            PcIdentityToken = pcIdentityToken,
            CreatedAt      = createdAt,
            ExpiresAt      = createdAt.AddSeconds(120),
            State          = PairingSessionState.PendingScan,
        };
    }
}
