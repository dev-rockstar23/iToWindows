// Feature: pc-unlock, Property 8
// Nonce uniqueness and length — property-based tests.
// Validates: Requirements 5.1
//
// Property 8: Generate 1000 nonces; all exactly 32 bytes; all distinct.
// Collision probability ≈ N²/(2·2^256) ≈ negligible for 32-byte CSPRNG output

using FsCheck;
using FsCheck.Fluent;
using FsCheck.Xunit;
using PCUnlockService.Crypto;
using Xunit;

namespace PCUnlockService.Tests.Crypto;

/// <summary>
/// Unit (example-based) tests for <see cref="NonceGenerator"/>.
/// Validates: Requirements 5.1
/// </summary>
public sealed class NonceFactTests
{
    /// <summary>
    /// A single generated nonce MUST be exactly <see cref="NonceGenerator.NonceLength"/>
    /// (32) bytes (Requirement 5.1).
    /// </summary>
    [Fact]
    public void GenerateNonce_Returns32Bytes()
    {
        // Feature: pc-unlock, Property 8
        byte[] nonce = NonceGenerator.Generate();

        Assert.Equal(NonceGenerator.NonceLength, nonce.Length);
        Assert.Equal(32, nonce.Length);
    }

    /// <summary>
    /// 1000 independently generated nonces MUST all be distinct when
    /// hex-encoded (Requirement 5.1).
    ///
    /// // Collision probability ≈ N²/(2·2^256) ≈ negligible for 32-byte CSPRNG output
    /// </summary>
    [Fact]
    public void GenerateNonces_1000_AllDistinct()
    {
        // Feature: pc-unlock, Property 8
        const int Count = 1000;
        var hexSet = new HashSet<string>(Count);

        for (int i = 0; i < Count; i++)
        {
            string hex = Convert.ToHexString(NonceGenerator.Generate());
            hexSet.Add(hex);
        }

        // Collision probability ≈ N²/(2·2^256) ≈ negligible for 32-byte CSPRNG output
        Assert.Equal(Count, hexSet.Count);
    }
}

// ---------------------------------------------------------------------------
// Generators for Property 8
// ---------------------------------------------------------------------------

internal static class NonceGenerators
{
    /// <summary>
    /// Arbitrary for N in the range [1, 50] — used to parameterise the
    /// "N generated nonces all have length 32" property.
    /// </summary>
    public static Arbitrary<int> CountInRange1To50() =>
        Gen.Choose(1, 50).ToArbitrary();
}

// ---------------------------------------------------------------------------
// Property-based tests — Property 8 (FsCheck)
// ---------------------------------------------------------------------------

/// <summary>
/// Property-based tests for nonce uniqueness and length (Property 8).
/// Validates: Requirements 5.1 — minimum 100 iterations.
/// </summary>
public sealed class NoncePropertyTests
{
    // -----------------------------------------------------------------------
    // Wrapper types for [Property(Arbitrary = ...)] approach
    // -----------------------------------------------------------------------

    /// <summary>Wrapper: an integer in [1, 50] representing a nonce batch size.</summary>
    public readonly record struct NonceCount(int Value);

    /// <summary>FsCheck arbitrary for <see cref="NonceCount"/>.</summary>
    public static Arbitrary<NonceCount> ArbitraryNonceCount() =>
        NonceGenerators.CountInRange1To50()
                       .Select(n => new NonceCount(n))
                       .ToArbitrary();

    // -----------------------------------------------------------------------
    // Property 8a — for any N in [1..50]: all N nonces have length 32
    // -----------------------------------------------------------------------

    /// <summary>
    /// **Validates: Requirements 5.1**
    ///
    /// For any N in [1, 50], every nonce in a batch of N generated nonces MUST
    /// have exactly 32 bytes (= <see cref="NonceGenerator.NonceLength"/>).
    /// </summary>
    [Property(MaxTest = 100, Arbitrary = new[] { typeof(NoncePropertyTests) })]
    public Property BatchOfNNonces_AllHaveLength32(NonceCount count)
    {
        // Feature: pc-unlock, Property 8
        for (int i = 0; i < count.Value; i++)
        {
            byte[] nonce = NonceGenerator.Generate();
            if (nonce.Length != NonceGenerator.NonceLength)
            {
                return false
                    .Label($"Nonce at index {i} has length {nonce.Length}, expected {NonceGenerator.NonceLength}");
            }
        }

        return true.Label($"All {count.Value} nonces have length {NonceGenerator.NonceLength}");
    }

    /// <summary>
    /// **Validates: Requirements 5.1** — Prop.ForAll variant.
    ///
    /// Same assertion driven via <see cref="Prop.ForAll{T}"/> with explicit
    /// <see cref="Configuration"/> (MaxTest = 100).
    /// </summary>
    [Fact]
    public void Property8a_BatchNonces_AllLength32_PropForAll()
    {
        // Feature: pc-unlock, Property 8
        var cfg = Configuration.QuickThrowOnFailure.WithMaxTest(100);

        var prop = Prop.ForAll(
            NonceGenerators.CountInRange1To50(),
            n =>
            {
                for (int i = 0; i < n; i++)
                {
                    byte[] nonce = NonceGenerator.Generate();
                    if (nonce.Length != NonceGenerator.NonceLength)
                        return false.Label($"Nonce[{i}] length {nonce.Length} ≠ {NonceGenerator.NonceLength}");
                }
                return true.Label($"All {n} nonces have correct length");
            });

        prop.Check(cfg);
    }

    // -----------------------------------------------------------------------
    // Property 8b — for any two independently generated nonces: not equal
    //
    // Collision probability ≈ N²/(2·2^256) ≈ negligible for 32-byte CSPRNG output
    // -----------------------------------------------------------------------

    /// <summary>
    /// **Validates: Requirements 5.1**
    ///
    /// Any two independently generated nonces MUST NOT be equal.
    ///
    /// // Collision probability ≈ N²/(2·2^256) ≈ negligible for 32-byte CSPRNG output
    /// </summary>
    [Fact]
    public void Property8b_TwoNonces_AreNotEqual_PropForAll()
    {
        // Feature: pc-unlock, Property 8
        // Collision probability ≈ N²/(2·2^256) ≈ negligible for 32-byte CSPRNG output
        var cfg = Configuration.QuickThrowOnFailure.WithMaxTest(100);

        // Each iteration generates two fresh nonces independently and asserts
        // they differ.  There is no meaningful FsCheck input to vary here — the
        // randomness comes from the CSPRNG inside NonceGenerator.Generate().
        // We use a trivial unit input (bool) to satisfy the ForAll signature.
        var prop = Prop.ForAll(
            Arb.Generate<bool>().ToArbitrary(),
            _ =>
            {
                byte[] a = NonceGenerator.Generate();
                byte[] b = NonceGenerator.Generate();

                // Collision probability ≈ N²/(2·2^256) ≈ negligible for 32-byte CSPRNG output
                return (!a.SequenceEqual(b))
                    .Label("Two independently generated nonces must not be equal");
            });

        prop.Check(cfg);
    }
}
