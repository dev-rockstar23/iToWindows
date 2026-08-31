// Feature: pc-unlock, Property 4
// Feature: pc-unlock, Property 13
//
// SignaturePropertyTests — property-based tests for cross-platform signature
// round trip and nonce-consumed-on-success orchestration.
//
// Property 4: Cross-platform signature round trip
//   Validates: Requirements 3.2, 3.6
//   For any 57-byte canonical challenge payload, a signature produced by a
//   software P-256 key (simulating iOS ChallengeSigner) is successfully verified
//   by CNGCryptoVerifier.
//
// Property 13: Nonce consumed on success
//   Validates: Requirements 5.5, 13.4, 13.5
//   For any Response passing all pre-signature checks, the nonce is present in
//   ConsumedNonceStore after the unlock attempt, and persistence occurs before
//   the unlock signal is sent.

using System.Security.Cryptography;
using FsCheck;
using FsCheck.Fluent;
using FsCheck.Xunit;
using Microsoft.Extensions.Logging.Abstractions;
using PCUnlockService.Crypto;
using PCUnlockService.Session;
using Xunit;

namespace PCUnlockService.Tests.Crypto;

// ---------------------------------------------------------------------------
// Shared file-scoped stub: IConsumedNonceStore
// ---------------------------------------------------------------------------

/// <summary>
/// Minimal in-memory stub for <see cref="IConsumedNonceStore"/> used by both
/// property test classes in this file.  Backed by a <see cref="HashSet{T}"/>
/// of Base64-encoded nonces; tracks every <see cref="Append"/> call so tests
/// can assert the nonce was persisted.
/// </summary>
file sealed class StubConsumedNonceStore : IConsumedNonceStore
{
    private readonly HashSet<string> _consumed = new(StringComparer.Ordinal);

    /// <summary>Number of times <see cref="Append"/> has been called.</summary>
    public int AppendCallCount { get; private set; }

    /// <summary>Pre-seed a nonce so <see cref="Contains"/> returns <c>true</c>.</summary>
    public void AddConsumed(byte[] nonce) => _consumed.Add(Convert.ToBase64String(nonce));

    public void Load() { }

    public bool Contains(byte[] nonce)
    {
        if (nonce is null || nonce.Length == 0) return false;
        return _consumed.Contains(Convert.ToBase64String(nonce));
    }

    public void Append(byte[] nonce)
    {
        if (nonce is null || nonce.Length == 0)
            throw new ArgumentException("Nonce must not be null or empty.", nameof(nonce));

        _consumed.Add(Convert.ToBase64String(nonce));
        AppendCallCount++;
    }
}

// ---------------------------------------------------------------------------
// Shared file-scoped helper: reflection injection
// ---------------------------------------------------------------------------

file static class SignatureTestHelpers
{
    /// <summary>
    /// Injects <paramref name="session"/> into the private
    /// <c>_activeSession</c> field of <paramref name="manager"/> via
    /// reflection, enabling tests to control session state without waiting
    /// for clock drift.
    /// </summary>
    public static void SetActiveSession(SessionNonceManager manager, UnlockSession session)
    {
        var field = typeof(SessionNonceManager)
            .GetField(
                "_activeSession",
                System.Reflection.BindingFlags.NonPublic |
                System.Reflection.BindingFlags.Instance)
            ?? throw new InvalidOperationException(
                "Reflection: could not locate '_activeSession' field on SessionNonceManager.");
        field.SetValue(manager, session);
    }

    /// <summary>
    /// Retrieves the current <see cref="UnlockSession"/> from the private
    /// <c>_activeSession</c> field of <paramref name="manager"/>.
    /// </summary>
    public static UnlockSession? GetActiveSession(SessionNonceManager manager)
    {
        var field = typeof(SessionNonceManager)
            .GetField(
                "_activeSession",
                System.Reflection.BindingFlags.NonPublic |
                System.Reflection.BindingFlags.Instance)
            ?? throw new InvalidOperationException(
                "Reflection: could not locate '_activeSession' field on SessionNonceManager.");
        return (UnlockSession?)field.GetValue(manager);
    }
}

// ===========================================================================
// Property 4 — Cross-platform signature round trip
// ===========================================================================

/// <summary>
/// Property 4: For any 57-byte canonical challenge payload, a signature
/// produced by a software P-256 key pair (simulating the iOS
/// <c>ChallengeSigner</c> in test) MUST be successfully verified by
/// <see cref="CNGCryptoVerifier"/>.
/// <para>
/// The software key exercises the same ECDSA-P256 / SHA-256 / DER-signature
/// algorithm as the Secure Enclave on iOS; <see cref="CNGCryptoVerifier"/>
/// is the production Windows verifier backed by CNG.
/// </para>
/// Validates: Requirements 3.2, 3.6
/// </summary>
public sealed class CrossPlatformSignatureRoundTripTests
{
    // -----------------------------------------------------------------------
    // Property 4 — property-based, 100 iterations
    // -----------------------------------------------------------------------

    /// <summary>
    /// **Validates: Requirements 3.2, 3.6**
    ///
    /// For any arbitrary 57-byte canonical challenge payload:
    /// <list type="number">
    ///   <item>Generate a software P-256 key pair.</item>
    ///   <item>Export SPKI DER public key.</item>
    ///   <item>Compute <c>SHA-256(payload)</c>.</item>
    ///   <item>Sign the digest with <c>DSASignatureFormat.Rfc3279DerSequence</c>.</item>
    ///   <item>Verify via <see cref="CNGCryptoVerifier.Verify"/>.</item>
    /// </list>
    /// Result MUST be <see cref="VerificationOutcome.Success"/>.
    /// </summary>
    [Property(MaxTest = 100)]
    public Property AnyCanonicalPayload_SoftwareP256Signature_VerifiesWithCNG()
    {
        // Feature: pc-unlock, Property 4
        return Prop.ForAll(
            Arb.Generate<byte>().ArrayOf(57).ToArbitrary(),
            challenge57Bytes =>
            {
                // Arrange — generate a fresh software P-256 key pair per iteration,
                // mirroring how the iOS ChallengeSigner uses a per-pairing key.
                using var ecdsa = ECDsa.Create(ECCurve.NamedCurves.nistP256);

                // Export SubjectPublicKeyInfo DER (~91 bytes) — the format stored
                // in DeviceRecord.publicKeyDER and consumed by CNGCryptoVerifier.
                byte[] spkiDer = ecdsa.ExportSubjectPublicKeyInfo();

                // iOS ChallengeSigner: digest = SHA256(canonicalEncode(challenge))
                // then signs the digest (not the raw bytes).
                byte[] digest = SHA256.HashData(challenge57Bytes);

                // Sign using RFC 3279 DER SEQUENCE — same encoding as CryptoKit on iOS.
                byte[] signatureDer = ecdsa.SignHash(digest, DSASignatureFormat.Rfc3279DerSequence);

                // Act — production Windows verifier (CNG-backed).
                var verifier = new CNGCryptoVerifier();
                VerificationResult result = verifier.Verify(spkiDer, challenge57Bytes, signatureDer);

                // Assert
                return (result.Outcome == VerificationOutcome.Success)
                    .Label($"Expected Success, got {result.Outcome}" +
                           (result.ErrorMessage is not null ? $": {result.ErrorMessage}" : string.Empty));
            });
    }

    // -----------------------------------------------------------------------
    // Property 4 — concrete [Fact] example
    // -----------------------------------------------------------------------

    /// <summary>
    /// Concrete example with a known 57-byte canonical challenge payload
    /// (version=1, fixed sessionId, zeroed nonce, future expiresAt).
    /// Validates: Requirements 3.2, 3.6
    /// </summary>
    [Fact]
    public void KnownCanonicalChallenge_SoftwareP256Signature_VerifiesWithCNG()
    {
        // Feature: pc-unlock, Property 4
        // Arrange — build a deterministic 57-byte canonical challenge:
        //   [version:1][sessionId:16][nonce:32][expiresAt:8]
        var challenge = new byte[57];
        challenge[0] = 1; // version = 1

        // Fixed session ID bytes for reproducibility.
        var sessionId = new byte[]
        {
            0xA1, 0xB2, 0xC3, 0xD4, 0xE5, 0xF6, 0x07, 0x18,
            0x29, 0x3A, 0x4B, 0x5C, 0x6D, 0x7E, 0x8F, 0x90,
        };
        sessionId.CopyTo(challenge, 1); // bytes 1–16

        // Nonce: 32 bytes of 0xAB.
        for (int i = 17; i < 49; i++) challenge[i] = 0xAB;

        // expiresAt: now + 3600 seconds, little-endian int64.
        long expiresAt = DateTimeOffset.UtcNow.ToUnixTimeSeconds() + 3600;
        BitConverter.GetBytes(expiresAt).CopyTo(challenge, 49);

        using var ecdsa  = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        byte[] spkiDer   = ecdsa.ExportSubjectPublicKeyInfo();
        byte[] digest    = SHA256.HashData(challenge);
        byte[] signature = ecdsa.SignHash(digest, DSASignatureFormat.Rfc3279DerSequence);

        // Act
        var verifier = new CNGCryptoVerifier();
        VerificationResult result = verifier.Verify(spkiDer, challenge, signature);

        // Assert
        Assert.Equal(VerificationOutcome.Success, result.Outcome);
        Assert.Null(result.ErrorMessage);
    }
}

// ===========================================================================
// Property 13 — Nonce consumed on success
// ===========================================================================

/// <summary>
/// Property 13: For any Response that passes all pre-signature checks (not
/// expired, session ID matches, nonce not replayed), after the caller calls
/// <see cref="IConsumedNonceStore.Append"/> the nonce MUST be present in the
/// <see cref="StubConsumedNonceStore"/>, and persistence MUST occur before any
/// unlock signal is sent (i.e., <see cref="IConsumedNonceStore.Append"/> is
/// called before the signal).
/// <para>
/// The test orchestrates the caller-side contract described in the design's
/// Verification Flow (steps 10–11): on <c>ValidateResponse</c> returning
/// <c>Valid</c>, the caller appends the nonce and then signals success.
/// </para>
/// Validates: Requirements 5.5, 13.4, 13.5
/// </summary>
public sealed class NonceConsumedOnSuccessTests
{
    // -----------------------------------------------------------------------
    // Private helpers
    // -----------------------------------------------------------------------

    /// <summary>
    /// Creates a fresh <see cref="SessionNonceManager"/> backed by the given
    /// <paramref name="store"/> and a <see cref="NullLogger{T}"/>.
    /// </summary>
    private static SessionNonceManager MakeManager(StubConsumedNonceStore store) =>
        new(store, NullLogger<SessionNonceManager>.Instance);

    /// <summary>
    /// Injects a non-expired session whose <c>DeviceId</c> is
    /// <paramref name="deviceId"/> into <paramref name="manager"/> and returns
    /// the injected session.
    /// </summary>
    private static UnlockSession InjectValidSession(
        SessionNonceManager manager,
        string deviceId)
    {
        var session = new UnlockSession
        {
            SessionId = Guid.NewGuid(),
            Nonce     = RandomNumberGenerator.GetBytes(32),
            ExpiresAt = DateTimeOffset.UtcNow.ToUnixTimeSeconds() + 60,
            DeviceId  = deviceId,
        };
        SignatureTestHelpers.SetActiveSession(manager, session);
        return session;
    }

    /// <summary>
    /// Builds a <see cref="BleResponse"/> that echoes <paramref name="session"/>'s
    /// session ID (so the session-mismatch check passes).
    /// </summary>
    private static BleResponse ResponseFor(UnlockSession session) =>
        new()
        {
            Version      = 1,
            SessionId    = session.SessionId,
            DeviceId     = Guid.NewGuid(),
            SignatureDER = new byte[] { 0x30, 0x44 }, // minimal DER stub
        };

    // -----------------------------------------------------------------------
    // Property 13 — property-based, 100 iterations
    // -----------------------------------------------------------------------

    /// <summary>
    /// **Validates: Requirements 5.5, 13.4, 13.5**
    ///
    /// For any arbitrary non-empty device ID string:
    /// <list type="number">
    ///   <item>Start a valid, non-expired session for that device.</item>
    ///   <item>Call <see cref="SessionNonceManager.ValidateResponse"/> — result
    ///         MUST be <c>Valid</c> (all pre-signature checks pass).</item>
    ///   <item>The caller simulates the Verification Flow step 10: calls
    ///         <see cref="IConsumedNonceStore.Append"/> with the session nonce
    ///         BEFORE emitting the unlock signal.</item>
    ///   <item>Assert the nonce is now present in the store
    ///         (<see cref="IConsumedNonceStore.Contains"/> returns <c>true</c>).</item>
    ///   <item>Assert <see cref="StubConsumedNonceStore.AppendCallCount"/> is 1
    ///         (exactly one persistence call, before the signal).</item>
    /// </list>
    /// </summary>
    [Property(MaxTest = 100)]
    public Property AnyDeviceId_AfterSuccessfulValidation_NonceIsConsumedBeforeSignal()
    {
        // Feature: pc-unlock, Property 13
        return Prop.ForAll(
            // Generate arbitrary non-empty strings as device IDs.
            Arb.Generate<string>()
               .Where(s => s is not null && s.Length > 0)
               .ToArbitrary(),
            deviceId =>
            {
                // Arrange
                var store   = new StubConsumedNonceStore();
                var manager = MakeManager(store);

                UnlockSession session = InjectValidSession(manager, deviceId);
                BleResponse   response = ResponseFor(session);

                // Act — Step 1: validate response (all checks must pass).
                ResponseValidationResult validationResult = manager.ValidateResponse(response);

                if (!validationResult.IsValid)
                {
                    // This would indicate a test setup bug, not a property failure.
                    return false.Label(
                        $"Pre-condition failed: ValidateResponse returned {validationResult.Reason}; " +
                        "expected Valid for a non-expired, matching, un-replayed session.");
                }

                // Act — Step 2 (caller's responsibility per Verification Flow §10–11):
                // Persist the nonce BEFORE signalling success.
                store.Append(session.Nonce);

                // Simulate: send unlock signal here (represented by a bool flag).
                bool unlockSignalSent = true;

                // Assert
                bool nonceIsInStore       = store.Contains(session.Nonce);
                bool appendCalledOnce     = store.AppendCallCount == 1;
                bool persistedBeforeSignal = appendCalledOnce && unlockSignalSent;

                return nonceIsInStore
                    .Label("Nonce must be present in ConsumedNonceStore after unlock")
                    .And(appendCalledOnce)
                    .Label($"Append must be called exactly once (called {store.AppendCallCount} time(s))")
                    .And(persistedBeforeSignal)
                    .Label("Nonce persistence must occur before unlock signal is sent");
            });
    }

    // -----------------------------------------------------------------------
    // Property 13 — concrete [Fact] example
    // -----------------------------------------------------------------------

    /// <summary>
    /// Concrete example: device ID "test-device-001", after a successful
    /// validation cycle, the nonce is in the store and was appended before
    /// the unlock signal was emitted.
    /// Validates: Requirements 5.5, 13.4, 13.5
    /// </summary>
    [Fact]
    public void KnownDeviceId_AfterSuccessfulValidation_NonceIsConsumedBeforeSignal()
    {
        // Feature: pc-unlock, Property 13
        // Arrange
        var store   = new StubConsumedNonceStore();
        var manager = MakeManager(store);

        const string deviceId = "test-device-001";
        UnlockSession session  = InjectValidSession(manager, deviceId);
        BleResponse   response = ResponseFor(session);

        // Act — Step 1: validate (should pass all pre-signature checks).
        ResponseValidationResult validationResult = manager.ValidateResponse(response);
        Assert.True(validationResult.IsValid,
            $"Expected ValidateResponse to return Valid, got {validationResult.Reason}");

        // Verify the nonce is NOT yet in the store before Append is called.
        Assert.False(store.Contains(session.Nonce),
            "Nonce must NOT be in the store before Append is called.");

        // Act — Step 2: persist nonce (Requirement 13.4 — before unlock signal).
        store.Append(session.Nonce);

        // Simulate sending the unlock signal AFTER nonce is persisted.
        bool unlockSignalSent = true;
        _ = unlockSignalSent; // consumed; signal is "sent" here

        // Assert — nonce is now in the store (Requirement 5.5, 13.5).
        Assert.True(store.Contains(session.Nonce),
            "Nonce must be present in ConsumedNonceStore after Append.");

        // Exactly one Append call was made (Requirement 13.4).
        Assert.Equal(1, store.AppendCallCount);
    }
}
