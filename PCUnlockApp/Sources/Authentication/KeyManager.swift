// Feature: pc-unlock
// KeyManager — generates, loads, and deletes Secure Enclave P-256 signing key pairs.
// Requirements: 2.4, 2.5, 3.1, 3.7

import Foundation
import CryptoKit

// MARK: - Protocol

/// Defines the key-lifecycle contract for pairing-scoped P-256 key pairs.
///
/// The private key is created inside the Secure Enclave and never exported as
/// raw key bytes (Requirement 2.4).  Only the opaque `dataRepresentation` blob
/// is persisted, via `SecureKeyStoring`.
public protocol KeyManaging {
    /// Generates a new P-256 Secure Enclave key pair for the given pairing.
    ///
    /// Any previously stored key pair for this pairing is securely deleted
    /// **before** the new key is created (Requirement 3.7).  The private key is
    /// created with `.biometryCurrentSet` access control so the key is
    /// automatically invalidated if the enrolled biometrics change (Requirement
    /// 2.5).
    ///
    /// - Parameter pairingID: The UUID that scopes the key pair to a specific PC
    ///   pairing.
    /// - Returns: The `P256.Signing.PublicKey` associated with the newly created
    ///   private key.  The public key may be freely transmitted to the paired PC.
    /// - Throws: Any error produced by the Secure Enclave key generation or the
    ///   underlying `SecureKeyStoring` implementation.
    func generateKeyPair(forPairing pairingID: UUID) throws -> P256.Signing.PublicKey

    /// Retrieves the Secure Enclave private key for the given pairing.
    ///
    /// - Parameter pairingID: The pairing whose private key should be loaded.
    /// - Returns: The reconstructed `SecureEnclave.P256.Signing.PrivateKey`.
    /// - Throws: `SecureKeyStoreError.itemNotFound` if no key exists for the
    ///   pairing, `SecureKeyStoreError.itemCorrupt` if the stored blob is
    ///   invalid (e.g. biometrics changed), or a keychain error otherwise.
    func loadPrivateKey(forPairing pairingID: UUID) throws -> SecureEnclave.P256.Signing.PrivateKey

    /// Permanently removes the key pair stored for the given pairing.
    ///
    /// Silently succeeds if no key exists for the pairing.
    ///
    /// - Parameter pairingID: The pairing whose key pair should be deleted.
    /// - Throws: Any error produced by the underlying `SecureKeyStoring`
    ///   implementation.
    func deleteKeyPair(forPairing pairingID: UUID) throws
}

// MARK: - Errors

/// Errors that can be thrown by `KeyManager` operations beyond those
/// propagated from `SecureKeyStoring`.
public enum KeyManagerError: Error, Equatable {
    /// The current device does not have a Secure Enclave, so P-256 SE keys
    /// cannot be created.  This satisfies Requirement 3.1 — on hardware that
    /// lacks a Secure Enclave the operation must fail rather than silently
    /// falling back to a software key.
    case secureEnclaveUnavailable
}

// MARK: - Implementation

/// Concrete implementation of `KeyManaging` that uses
/// `SecureEnclave.P256.Signing.PrivateKey` with `.biometryCurrentSet` access
/// control and delegates persistence to a `SecureKeyStoring` instance.
///
/// ### Key generation sequence (Requirement 3.7)
/// 1. Delete any existing Keychain item for `pairingID`.
/// 2. Create a new `SecureEnclave.P256.Signing.PrivateKey`.
/// 3. Store the opaque `dataRepresentation` via `SecureKeyStoring`.
/// 4. Return the public key.
///
/// Step 1 happens unconditionally so that a crash between steps 2 and 3 on a
/// subsequent call will still clean up the dangling Keychain entry first.
public final class KeyManager: KeyManaging {

    // MARK: - Dependencies

    private let secureKeyStore: SecureKeyStoring

    // MARK: - Init

    /// Creates a `KeyManager` with the given key-store backend.
    ///
    /// - Parameter secureKeyStore: The storage layer for opaque key blobs.
    ///   Defaults to `SecureKeyStore()` for production use.
    public init(secureKeyStore: SecureKeyStoring = SecureKeyStore()) {
        self.secureKeyStore = secureKeyStore
    }

    // MARK: - KeyManaging

    public func generateKeyPair(forPairing pairingID: UUID) throws -> P256.Signing.PublicKey {
        // Requirement 3.1: Only generate SE keys; refuse on hardware without SE.
        guard SecureEnclave.isAvailable else {
            throw KeyManagerError.secureEnclaveUnavailable
        }

        // Requirement 3.7: Delete any previously stored key pair for this
        // pairing BEFORE generating the new one.  `delete` is a no-op when no
        // item exists, so this is always safe to call.
        try secureKeyStore.delete(forPairing: pairingID)

        // Requirement 2.5: Create the key with `.biometryCurrentSet` so it is
        // invalidated automatically when enrolled biometrics change.
        // Requirement 3.1: Use the CryptoKit Secure Enclave P-256 API.
        let accessControl = SecAccessControlCreateWithFlags(
            nil,
            kSecAttrAccessibleWhenUnlockedThisDeviceOnly,
            [.privateKeyUsage, .biometryCurrentSet],
            nil
        )!

        let privateKey = try SecureEnclave.P256.Signing.PrivateKey(
            accessControl: accessControl
        )

        // Requirement 2.4: Only the opaque `dataRepresentation` blob is stored;
        // raw private key bytes never leave the Secure Enclave.
        try secureKeyStore.store(privateKey, forPairing: pairingID)

        return privateKey.publicKey
    }

    public func loadPrivateKey(forPairing pairingID: UUID) throws -> SecureEnclave.P256.Signing.PrivateKey {
        // Delegate entirely to the store — it handles deserialization and
        // maps missing/corrupt items to the appropriate `SecureKeyStoreError`.
        try secureKeyStore.load(forPairing: pairingID)
    }

    public func deleteKeyPair(forPairing pairingID: UUID) throws {
        try secureKeyStore.delete(forPairing: pairingID)
    }
}
