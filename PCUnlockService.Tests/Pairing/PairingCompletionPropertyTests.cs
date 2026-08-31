// Feature: pc-unlock, Property 16
// Pairing completion writes device record — property-based tests.
// Validates: Requirements 6.5
//
// Property 16: For any completed pairing where both sides confirm within
// 120 seconds, the Device Registry MUST contain a DeviceRecord with:
//   1. result.Outcome == PairingOutcome.Success
//   2. result.Device != null
//   3. result.Device.PublicKeyDER sequence-equals the publicKeyDER supplied
//   4. result.Device.PcIdentityToken.Length == 16
//   5. result.Device.DeviceName == deviceName
//   6. result.Device.DeviceId != Guid.Empty

using FsCheck;
using FsCheck.Fluent;
using FsCheck.Xunit;
using PCUnlockService.Pairing;
using Xunit;

namespace PCUnlockService.Tests.Pairing;

// ---------------------------------------------------------------------------
// CapturingBLEChannel
// A BLE pairing channel that waits until the test provides the correct
// pairing code (extracted from handler log output) before returning the
// PairingRequest to the handler.  This lets us echo the right code back
// without subclassing the sealed PairingHandler.
// ---------------------------------------------------------------------------

/// <summary>
/// BLE pairing channel that coordinates with the test harness via a
/// <see cref="TaskCompletionSource{T}"/>.  The test drives it by calling
/// <see cref="ProvideCode"/> once the pairing code has been extracted from the
/// log output; this unblocks <see cref="AwaitPairingRequestAsync"/> and
/// returns a <see cref="PairingRequest"/> that echoes the correct code.
/// </summary>
internal sealed class CapturingBLEChannel : IBLEPairingChannel
{
    private readonly TaskCompletionSource<string> _codeTcs =
        new(TaskCreationOptions.RunContinuationsAsynchronously);

    private readonly byte[] _publicKeyDER;

    /// <param name="publicKeyDER">
    ///   Public key bytes to embed in the returned <see cref="PairingRequest"/>.
    /// </param>
    public CapturingBLEChannel(byte[] publicKeyDER)
    {
        _publicKeyDER = publicKeyDER;
    }

    /// <inheritdoc/>
    public async Task<PairingRequest?> AwaitPairingRequestAsync(CancellationToken ct)
    {
        // Block until the test provides the correct code, or until ct fires.
        string code = await _codeTcs.Task.WaitAsync(ct).ConfigureAwait(false);

        return new PairingRequest
        {
            PublicKeyDER    = _publicKeyDER,
            PairingCodeEcho = code,
        };
    }

    /// <inheritdoc/>
    public Task SendPairingCompleteAsync(CancellationToken ct) => Task.CompletedTask;

    /// <summary>
    /// Called by the test after extracting the pairing code from the handler's
    /// log output. Unblocks <see cref="AwaitPairingRequestAsync"/>.
    /// </summary>
    public void ProvideCode(string code) => _codeTcs.TrySetResult(code);
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// <summary>
/// Shared helpers for Property 16 tests: code extraction from log messages
/// and the full async pairing orchestration wired into a sync wrapper.
/// </summary>
internal static class PairingCompletionHelpers
{
    /// <summary>
    /// Device names used by the FsCheck arbitrary generator.
    /// Using a fixed set keeps tests fast and deterministic in character.
    /// </summary>
    public static readonly string[] DeviceNames =
    [
        "Alice's iPhone",
        "Test Device",
        "Bob iPhone 15",
    ];

    /// <summary>
    /// Polls a <see cref="RecordingLogger{T}"/> until the handler logs the
    /// PairingPayload JSON containing <c>"code":"XXXXXX"</c>, then returns
    /// the 6-character code value.  Returns <c>null</c> if the code is not
    /// found within the polling window.
    /// </summary>
    public static async Task<string?> WaitForPairingCodeAsync(
        RecordingLogger<PairingHandler> logger,
        CancellationToken ct)
    {
        const int PollMs    = 5;
        const int MaxWaitMs = 5_000;
        int elapsed = 0;

        while (elapsed < MaxWaitMs)
        {
            foreach (string msg in logger.Messages)
            {
                // PairingHandler logs: "... PairingPayload JSON: { ... "code":"XXXXXX" ... }"
                int codeIdx = msg.IndexOf("\"code\":", StringComparison.Ordinal);
                if (codeIdx >= 0)
                {
                    int start = msg.IndexOf('"', codeIdx + 7);
                    if (start >= 0)
                    {
                        int end = msg.IndexOf('"', start + 1);
                        if (end > start)
                            return msg.Substring(start + 1, end - start - 1);
                    }
                }
            }

            await Task.Delay(PollMs, ct).ConfigureAwait(false);
            elapsed += PollMs;
        }

        return null;
    }

    /// <summary>
    /// Runs a complete, successful pairing for the given
    /// <paramref name="deviceName"/> and <paramref name="publicKeyDER"/>:
    /// <list type="number">
    ///   <item>Creates a <see cref="CapturingBLEChannel"/> seeded with the public key.</item>
    ///   <item>Starts <see cref="PairingHandler.StartPairingAsync"/> on a background task.</item>
    ///   <item>Extracts the 6-char pairing code from the handler's log output.</item>
    ///   <item>Feeds the code back to the channel so the handler can verify it.</item>
    ///   <item>Awaits the result with a 5-second guard timeout.</item>
    /// </list>
    /// Throws <see cref="TimeoutException"/> if the full flow does not complete
    /// within 5 seconds (prevents property tests from hanging indefinitely).
    /// </summary>
    public static async Task<PairingResult> RunSuccessfulPairingAsync(
        string deviceName,
        byte[] publicKeyDER)
    {
        var logger  = new RecordingLogger<PairingHandler>();
        var channel = new CapturingBLEChannel(publicKeyDER);
        var handler = new PairingHandler(channel, logger);

        using var cts = new CancellationTokenSource(TimeSpan.FromSeconds(5));

        // Start pairing on a background task — it will suspend in
        // AwaitPairingRequestAsync until we call channel.ProvideCode().
        var pairingTask = handler.StartPairingAsync(deviceName, cts.Token);

        // Extract the code from the log output.
        string? code = await WaitForPairingCodeAsync(logger, cts.Token).ConfigureAwait(false);
        if (code is null)
            throw new TimeoutException(
                "Pairing code was not logged within 5 seconds.");

        // Echo the correct code back to unblock AwaitPairingRequestAsync.
        channel.ProvideCode(code);

        // Guard against the pairing task itself hanging.
        var completedTask = await Task
            .WhenAny(pairingTask, Task.Delay(TimeSpan.FromSeconds(5), cts.Token))
            .ConfigureAwait(false);

        if (completedTask != pairingTask)
            throw new TimeoutException(
                "PairingHandler.StartPairingAsync did not complete within 5 seconds.");

        return await pairingTask.ConfigureAwait(false);
    }

    /// <summary>
    /// Synchronous wrapper around <see cref="RunSuccessfulPairingAsync"/> for
    /// use inside FsCheck's synchronous <c>Property</c> delegates.
    /// </summary>
    public static PairingResult RunSuccessfulPairingSync(
        string deviceName,
        byte[] publicKeyDER) =>
        RunSuccessfulPairingAsync(deviceName, publicKeyDER)
            .GetAwaiter()
            .GetResult();
}

// ---------------------------------------------------------------------------
// Generators for Property 16
// ---------------------------------------------------------------------------

/// <summary>
/// FsCheck arbitraries for Property 16.
/// </summary>
internal static class PairingCompletionGenerators
{
    /// <summary>
    /// Generates device names from the fixed set defined in
    /// <see cref="PairingCompletionHelpers.DeviceNames"/>.
    /// </summary>
    public static Arbitrary<string> DeviceName() =>
        Arb.From(Gen.Elements(PairingCompletionHelpers.DeviceNames));

    /// <summary>
    /// Generates 91-byte arrays simulating a P-256 SPKI DER public key.
    /// The first byte is always 0x04 (uncompressed point marker) and the
    /// remaining 90 bytes are random, matching the size PairingHandler
    /// accepts without validation.
    /// </summary>
    public static Arbitrary<byte[]> PublicKeyDER() =>
        Gen.ArrayOf(91, Arb.Generate<byte>())
           .Select(bytes => { bytes[0] = 0x04; return bytes; })
           .ToArbitrary();
}

// ---------------------------------------------------------------------------
// Property 16 — FsCheck.Xunit [Property] attribute style
// ---------------------------------------------------------------------------

/// <summary>
/// Property-based tests for pairing completion writing the device record
/// (Property 16). Validates: Requirements 6.5 — minimum 100 iterations.
/// </summary>
public sealed class PairingCompletionPropertyTests
{
    // -----------------------------------------------------------------------
    // Strongly-typed input wrapper (required by [Property(Arbitrary = ...)])
    // -----------------------------------------------------------------------

    /// <summary>Wrapper carrying both inputs for the [Property] attribute approach.</summary>
    public readonly record struct PairingInputs(string DeviceName, byte[] PublicKeyDER);

    /// <summary>
    /// FsCheck arbitrary for <see cref="PairingInputs"/> — combines a device
    /// name from the fixed set and a 91-byte SPKI-shaped public key array.
    /// </summary>
    public static Arbitrary<PairingInputs> ArbitraryPairingInputs() =>
        (from name in PairingCompletionGenerators.DeviceName().Generator
         from key  in PairingCompletionGenerators.PublicKeyDER().Generator
         select new PairingInputs(name, key))
        .ToArbitrary();

    // -----------------------------------------------------------------------
    // [Property(MaxTest = 100)] — core Property 16 assertion
    // -----------------------------------------------------------------------

    /// <summary>
    /// **Validates: Requirements 6.5**
    ///
    /// For any completed pairing where both sides confirm within 120 seconds,
    /// the returned <see cref="PairingResult"/> MUST satisfy all six Device
    /// Registry invariants:
    /// <list type="number">
    ///   <item><see cref="PairingOutcome.Success"/></item>
    ///   <item><c>result.Device != null</c></item>
    ///   <item><c>result.Device.PublicKeyDER</c> sequence-equals the input key</item>
    ///   <item><c>result.Device.PcIdentityToken.Length == 16</c></item>
    ///   <item><c>result.Device.DeviceName == deviceName</c></item>
    ///   <item><c>result.Device.DeviceId != Guid.Empty</c></item>
    /// </list>
    /// </summary>
    [Property(MaxTest = 100, Arbitrary = new[] { typeof(PairingCompletionPropertyTests) })]
    public Property CompletedPairing_WritesCorrectDeviceRecord(PairingInputs inputs)
    {
        // Feature: pc-unlock, Property 16
        var result = PairingCompletionHelpers.RunSuccessfulPairingSync(
            inputs.DeviceName,
            inputs.PublicKeyDER);

        bool outcomeIsSuccess  = result.Outcome == PairingOutcome.Success;
        bool deviceNotNull     = result.Device != null;
        bool keyMatches        = deviceNotNull && result.Device!.PublicKeyDER.SequenceEqual(inputs.PublicKeyDER);
        bool tokenLength16     = deviceNotNull && result.Device!.PcIdentityToken.Length == 16;
        bool nameMatches       = deviceNotNull && result.Device!.DeviceName == inputs.DeviceName;
        bool idNotEmpty        = deviceNotNull && result.Device!.DeviceId != Guid.Empty;

        return outcomeIsSuccess
            .Label($"Outcome must be Success (was {result.Outcome})")
            .And(deviceNotNull)
            .Label("Device must not be null on successful pairing")
            .And(keyMatches)
            .Label("PublicKeyDER must match the key sent in the PairingRequest")
            .And(tokenLength16)
            .Label($"PcIdentityToken must be 16 bytes (was {result.Device?.PcIdentityToken.Length ?? -1})")
            .And(nameMatches)
            .Label($"DeviceName must match input (expected '{inputs.DeviceName}', got '{result.Device?.DeviceName}')")
            .And(idNotEmpty)
            .Label("DeviceId must not be Guid.Empty");
    }

    // -----------------------------------------------------------------------
    // Prop.ForAll variant — manual configuration (100 tests)
    // -----------------------------------------------------------------------

    /// <summary>
    /// **Validates: Requirements 6.5** — manual <c>Prop.ForAll</c> variant.
    ///
    /// Same six assertions as the [Property] test above, driven via
    /// <see cref="Prop.ForAll{T1,T2}"/> with explicit <see cref="Configuration"/>.
    /// </summary>
    [Fact]
    public void Property16_CompletedPairing_WritesDeviceRecord_PropForAll()
    {
        // Feature: pc-unlock, Property 16
        var cfg = Configuration.QuickThrowOnFailure.WithMaxTest(100);

        var prop = Prop.ForAll(
            PairingCompletionGenerators.DeviceName(),
            PairingCompletionGenerators.PublicKeyDER(),
            (deviceName, publicKeyDER) =>
            {
                var result = PairingCompletionHelpers.RunSuccessfulPairingSync(
                    deviceName, publicKeyDER);

                bool outcomeIsSuccess = result.Outcome == PairingOutcome.Success;
                bool deviceNotNull    = result.Device != null;
                bool keyMatches       = deviceNotNull && result.Device!.PublicKeyDER.SequenceEqual(publicKeyDER);
                bool tokenLength16    = deviceNotNull && result.Device!.PcIdentityToken.Length == 16;
                bool nameMatches      = deviceNotNull && result.Device!.DeviceName == deviceName;
                bool idNotEmpty       = deviceNotNull && result.Device!.DeviceId != Guid.Empty;

                return outcomeIsSuccess
                    .Label($"Outcome must be Success (was {result.Outcome})")
                    .And(deviceNotNull)
                    .Label("Device must not be null on successful pairing")
                    .And(keyMatches)
                    .Label("PublicKeyDER must match the key sent in the PairingRequest")
                    .And(tokenLength16)
                    .Label($"PcIdentityToken must be 16 bytes")
                    .And(nameMatches)
                    .Label($"DeviceName must match input")
                    .And(idNotEmpty)
                    .Label("DeviceId must not be Guid.Empty");
            });

        prop.Check(cfg);
    }
}

// ---------------------------------------------------------------------------
// Unit [Fact] tests — example-based verification of the same invariants
// ---------------------------------------------------------------------------

/// <summary>
/// Unit (example-based) tests for pairing completion device record writing
/// (Property 16). Validates: Requirements 6.5
/// </summary>
public sealed class PairingCompletionFactTests
{
    /// <summary>
    /// A successful pairing with a specific device name and public key MUST
    /// return <see cref="PairingOutcome.Success"/> with a populated
    /// <see cref="DeviceRecord"/>.
    /// </summary>
    [Fact]
    public async Task SuccessfulPairing_DeviceRecordContainsCorrectFields()
    {
        // Feature: pc-unlock, Property 16
        const string DeviceName = "Alice's iPhone";
        byte[] publicKey = new byte[91];
        publicKey[0] = 0x04;
        new Random(42).NextBytes(publicKey.AsSpan(1)); // deterministic fill for the test

        var result = await PairingCompletionHelpers.RunSuccessfulPairingAsync(
            DeviceName, publicKey);

        Assert.Equal(PairingOutcome.Success, result.Outcome);
        Assert.NotNull(result.Device);
        Assert.True(result.Device!.PublicKeyDER.SequenceEqual(publicKey),
            "PublicKeyDER must match the key sent by the iPhone");
        Assert.Equal(16, result.Device.PcIdentityToken.Length);
        Assert.Equal(DeviceName, result.Device.DeviceName);
        Assert.NotEqual(Guid.Empty, result.Device.DeviceId);
    }

    /// <summary>
    /// Two consecutive successful pairings with different device names MUST
    /// each produce a <see cref="DeviceRecord"/> carrying the correct name and
    /// a unique <see cref="DeviceRecord.DeviceId"/>.
    /// </summary>
    [Fact]
    public async Task TwoSuccessivePairings_ProduceIndependentDeviceRecords()
    {
        // Feature: pc-unlock, Property 16
        byte[] key1 = new byte[91]; key1[0] = 0x04;
        byte[] key2 = new byte[91]; key2[0] = 0x04;
        new Random(1).NextBytes(key1.AsSpan(1));
        new Random(2).NextBytes(key2.AsSpan(1));

        var r1 = await PairingCompletionHelpers.RunSuccessfulPairingAsync("Device A", key1);
        var r2 = await PairingCompletionHelpers.RunSuccessfulPairingAsync("Device B", key2);

        Assert.Equal(PairingOutcome.Success, r1.Outcome);
        Assert.Equal(PairingOutcome.Success, r2.Outcome);
        Assert.Equal("Device A", r1.Device!.DeviceName);
        Assert.Equal("Device B", r2.Device!.DeviceName);
        Assert.NotEqual(r1.Device.DeviceId, r2.Device.DeviceId);
        Assert.True(r1.Device.PublicKeyDER.SequenceEqual(key1));
        Assert.True(r2.Device.PublicKeyDER.SequenceEqual(key2));
    }

    /// <summary>
    /// The <see cref="DeviceRecord.PcIdentityToken"/> MUST be exactly 16 bytes
    /// and MUST NOT be all-zero (i.e. it was populated from BCryptGenRandom).
    /// </summary>
    [Fact]
    public async Task SuccessfulPairing_PcIdentityToken_Is16NonZeroBytes()
    {
        // Feature: pc-unlock, Property 16
        byte[] publicKey = new byte[91]; publicKey[0] = 0x04;

        var result = await PairingCompletionHelpers.RunSuccessfulPairingAsync(
            "Bob iPhone 15", publicKey);

        Assert.Equal(PairingOutcome.Success, result.Outcome);
        Assert.Equal(16, result.Device!.PcIdentityToken.Length);
        // Statistically impossible for a 16-byte random value to be all-zero.
        Assert.True(result.Device.PcIdentityToken.Any(b => b != 0),
            "PcIdentityToken must not be all-zero bytes");
    }

    /// <summary>
    /// The <see cref="DeviceRecord.PairedAt"/> timestamp MUST be set to a
    /// UTC value close to the time the pairing completed.
    /// </summary>
    [Fact]
    public async Task SuccessfulPairing_PairedAt_IsRecentUtcTimestamp()
    {
        // Feature: pc-unlock, Property 16
        var before = DateTimeOffset.UtcNow;
        byte[] publicKey = new byte[91]; publicKey[0] = 0x04;

        var result = await PairingCompletionHelpers.RunSuccessfulPairingAsync(
            "Test Device", publicKey);

        var after = DateTimeOffset.UtcNow;

        Assert.Equal(PairingOutcome.Success, result.Outcome);
        Assert.True(result.Device!.PairedAt >= before,
            "PairedAt must not be before the pairing started");
        Assert.True(result.Device.PairedAt <= after,
            "PairedAt must not be after the pairing completed");
        Assert.Null(result.Device.LastUsedAt);
    }
}
