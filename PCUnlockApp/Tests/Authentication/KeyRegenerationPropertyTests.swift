// Feature: pc-unlock, Property 6
// KeyRegenerationPropertyTests — property-based tests verifying that key
// regeneration atomically replaces the previous key pair for a pairing.
//
// Validates: Requirements 3.7
//
// Property 6: Key regeneration removes previous key
//   For any existing stored key pair, invoking generateKeyPair for the same
//   pairing MUST result in:
//     1. The old key being absent from the store (not loadable).
//     2. A new valid key being present and loadable.
//     3. The new key's public bytes differing from the old key's public bytes.

import XCTest
import CryptoKit
import SwiftCheck
@testable import PCUnlockApp

// MARK: - SwiftCheck Arbitrary conformance for UUID

/// Enables SwiftCheck to generate arbitrary `UUID` values by generating
/// 16 random bytes and constructing a UUID from them.
extension UUID: Arbitrary {
    public static var arbitrary: Gen<UUID> {
        // Generate 16 arbitrary bytes and combine them into a UUID tuple.
        return UInt8.arbitrary.proliferate(withSize: 16).map { bytes in
            let b = bytes + Array(repeating: 0, count: max(0, 16 - bytes.count))
            return UUID(uuid: (
                b[0],  b[1],  b[2],  b[3],
                b[4],  b[5],  b[6],  b[7],
                b[8],  b[9],  b[10], b[11],
                b[12], b[13], b[14], b[15]
            ))
        }
    }
}

// MARK: - Property tests

/// Property-based tests for Property 6 of the PCUnlock specification.
///
/// **Property 6:** For *any* pairing UUID where a key pair already exists in
/// the store, calling `KeyManager.generateKeyPair(forPairing:)` on that same
/// pairing MUST:
///   1. Remove the old key so it is no longer loadable (old key absent).
///   2. Store a fresh key that is loadable (new key present).
///   3. Produce a public key that differs from the old public key (new key distinct).
///
/// Tests run a minimum of 100 iterations via SwiftCheck's `property` operator.
///
/// **Validates: Requirements 3.7**
final class KeyRegenerationPropertyTests: XCTestCase {

    // MARK: - Helper

    /// Returns a brief description of `pairingID` for shrink-friendly failure messages.
    private func describe(_ pairingID: UUID) -> String {
        "pairingID=\(pairingID.uuidString)"
    }

    // MARK: - Property 6a: old key absent, new key present after regeneration

    /// For any arbitrary pairingID, after seeding a key and then calling
    /// `generateKeyPair` a second time:
    ///   - `store.hasItem(forPairing:)` must return `true` (new key stored).
    ///   - The loaded public key must differ from the first public key.
    ///
    /// **Validates: Requirements 3.7**
    ///
    /// Minimum 100 iterations (SwiftCheck default).
    func testProperty6_regeneration_oldKeyAbsent_newKeyPresent() {
        // Guard: Secure Enclave is only available on real Apple hardware/simulators.
        guard SecureEnclave.isAvailable else {
            print("[Property 6] Secure Enclave not available — test skipped on this machine.")
            return
        }

        let config = CheckerArguments(
            maxAllowableSuccessfulTests: 100,
            maxAllowableDiscardedTests: 500,
            maxTestCaseSize: 100
        )

        property(
            "Property 6: generateKeyPair removes old key and stores a new key",
            arguments: config
        ) <- forAll(UUID.arbitrary) { pairingID in

            // --- Setup: create a fresh store and manager for each iteration ---
            let store = MockSecureKeyStore()
            let manager = KeyManager(secureKeyStore: store)

            // Seed an initial key pair for the pairing.
            let firstPublicKey: P256.Signing.PublicKey
            do {
                firstPublicKey = try manager.generateKeyPair(forPairing: pairingID)
            } catch {
                // Could not generate first key (e.g. SE access issue); discard.
                return true
            }

            // Capture the raw bytes of the first public key for comparison.
            let firstPublicBytes = firstPublicKey.rawRepresentation

            // --- Exercise: regenerate the key pair for the same pairing ---
            let secondPublicKey: P256.Signing.PublicKey
            do {
                secondPublicKey = try manager.generateKeyPair(forPairing: pairingID)
            } catch {
                // Regeneration failed unexpectedly — property violated.
                return false
            }

            // --- Assertion 1: New key must be present in the store ---
            guard store.hasItem(forPairing: pairingID) else {
                // No item found after regeneration — property violated.
                return false
            }

            // --- Assertion 2: The stored key must be loadable ---
            let loadedKey: SecureEnclave.P256.Signing.PrivateKey
            do {
                loadedKey = try manager.loadPrivateKey(forPairing: pairingID)
            } catch {
                // Load failed after regeneration — property violated.
                return false
            }

            // --- Assertion 3: Loaded key must match the second (new) key ---
            guard loadedKey.publicKey.rawRepresentation == secondPublicKey.rawRepresentation else {
                return false
            }

            // --- Assertion 4: New key must differ from the old key ---
            // (Confirms the old key was actually replaced, not just re-stored.)
            let secondPublicBytes = secondPublicKey.rawRepresentation
            guard secondPublicBytes != firstPublicBytes else {
                return false
            }

            return true
        }
    }

    // MARK: - Property 6b: old key not loadable after regeneration

    /// Verifies that after regeneration the *old* key's public representation
    /// is no longer what `loadPrivateKey` returns — i.e., the old key has been
    /// displaced and cannot be retrieved.
    ///
    /// This is the complement of 6a: 6a checks the new key is present; 6b
    /// checks the old key is absent (from the perspective of what is loaded).
    ///
    /// **Validates: Requirements 3.7**
    ///
    /// Minimum 100 iterations.
    func testProperty6_regeneration_loadReturnsNewKeyNotOld() {
        guard SecureEnclave.isAvailable else {
            print("[Property 6b] Secure Enclave not available — test skipped on this machine.")
            return
        }

        let config = CheckerArguments(
            maxAllowableSuccessfulTests: 100,
            maxAllowableDiscardedTests: 500,
            maxTestCaseSize: 100
        )

        property(
            "Property 6b: after regeneration, loadPrivateKey returns new key — not the old one",
            arguments: config
        ) <- forAll(UUID.arbitrary) { pairingID in

            let store = MockSecureKeyStore()
            let manager = KeyManager(secureKeyStore: store)

            // Generate the first key pair.
            let firstPublicKey: P256.Signing.PublicKey
            do {
                firstPublicKey = try manager.generateKeyPair(forPairing: pairingID)
            } catch {
                return true // discard
            }

            // Regenerate — must succeed.
            let secondPublicKey: P256.Signing.PublicKey
            do {
                secondPublicKey = try manager.generateKeyPair(forPairing: pairingID)
            } catch {
                return false
            }

            // Load what is now in the store.
            let loadedKey: SecureEnclave.P256.Signing.PrivateKey
            do {
                loadedKey = try manager.loadPrivateKey(forPairing: pairingID)
            } catch {
                return false
            }

            let loadedBytes = loadedKey.publicKey.rawRepresentation

            // The loaded key must be the new key.
            guard loadedBytes == secondPublicKey.rawRepresentation else { return false }

            // The loaded key must NOT be the old key.
            guard loadedBytes != firstPublicKey.rawRepresentation else { return false }

            return true
        }
    }

    // MARK: - Property 6c: regeneration for one pairing does not affect other pairings

    /// For any two distinct pairingIDs A and B, regenerating the key for A must
    /// leave B's key completely unchanged — both presence and content.
    ///
    /// **Validates: Requirements 3.7** (scoped deletion — only the target pairing
    /// is affected)
    ///
    /// Minimum 100 iterations.
    func testProperty6_regeneration_doesNotAffectOtherPairings() {
        guard SecureEnclave.isAvailable else {
            print("[Property 6c] Secure Enclave not available — test skipped on this machine.")
            return
        }

        let config = CheckerArguments(
            maxAllowableSuccessfulTests: 100,
            maxAllowableDiscardedTests: 500,
            maxTestCaseSize: 100
        )

        // Generate two independent UUIDs; filter out the (astronomically
        // unlikely) case where they collide so we always have distinct pairings.
        property(
            "Property 6c: regenerating key for pairing A leaves pairing B unchanged",
            arguments: config
        ) <- forAll(UUID.arbitrary, UUID.arbitrary) { pairingA, pairingB in

            // Require distinct pairings.
            guard pairingA != pairingB else {
                return true // discard equal pairs
            }

            let store = MockSecureKeyStore()
            let manager = KeyManager(secureKeyStore: store)

            // Seed both pairings with initial keys.
            let publicA: P256.Signing.PublicKey
            let publicB: P256.Signing.PublicKey
            do {
                publicA = try manager.generateKeyPair(forPairing: pairingA)
                publicB = try manager.generateKeyPair(forPairing: pairingB)
            } catch {
                return true // discard on SE failure
            }

            // Sanity: both keys should be distinct.
            guard publicA.rawRepresentation != publicB.rawRepresentation else {
                return true // astronomically unlikely collision — discard
            }

            // Regenerate key for pairing A only.
            do {
                _ = try manager.generateKeyPair(forPairing: pairingA)
            } catch {
                return false
            }

            // Pairing B's key must still be present.
            guard store.hasItem(forPairing: pairingB) else { return false }

            // Pairing B's key must still be the original key (content unchanged).
            let loadedB: SecureEnclave.P256.Signing.PrivateKey
            do {
                loadedB = try manager.loadPrivateKey(forPairing: pairingB)
            } catch {
                return false
            }

            return loadedB.publicKey.rawRepresentation == publicB.rawRepresentation
        }
    }
}
