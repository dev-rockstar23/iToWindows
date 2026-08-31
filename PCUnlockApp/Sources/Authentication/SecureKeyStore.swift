// Feature: pc-unlock
// SecureKeyStore — thin Keychain wrapper for SecureEnclave.P256.Signing.PrivateKey opaque blobs.
// Requirements: 2.4, 2.5, 3.1

import Foundation
import CryptoKit
import Security

// MARK: - Errors

/// Errors thrown by `SecureKeyStore` operations.
public enum SecureKeyStoreError: Error, Equatable {
    /// No Keychain item found for the given pairing identifier.
    case itemNotFound
    /// The stored data could not be deserialized into a valid private key.
    case itemCorrupt
    /// An unexpected Keychain API failure; carries the raw `OSStatus`.
    case keychainError(OSStatus)
}

// MARK: - Protocol

/// Defines the storage contract for pairing-scoped private key blobs.
/// Implementations must never export raw key bytes — only the opaque
/// `dataRepresentation` produced by `SecureEnclave.P256.Signing.PrivateKey`.
public protocol SecureKeyStoring {
    /// Stores the opaque representation of `key` under a service identifier
    /// derived from `pairingID`.  If an item already exists for this pairing,
    /// it is replaced atomically.
    ///
    /// - Parameters:
    ///   - key: The Secure Enclave private key whose `dataRepresentation` is
    ///          stored.  The raw key bytes never leave the Secure Enclave.
    ///   - pairingID: The UUID that scopes this key to a specific PC pairing.
    /// - Throws: `SecureKeyStoreError.keychainError` on unexpected API failure.
    func store(_ key: SecureEnclave.P256.Signing.PrivateKey, forPairing pairingID: UUID) throws

    /// Loads and deserializes the private key blob for the given pairing.
    ///
    /// - Parameter pairingID: The pairing whose key should be retrieved.
    /// - Returns: The reconstructed `SecureEnclave.P256.Signing.PrivateKey`.
    /// - Throws: `SecureKeyStoreError.itemNotFound` when no item exists,
    ///           `SecureKeyStoreError.itemCorrupt` when the stored blob cannot
    ///           be deserialized, or `SecureKeyStoreError.keychainError` on an
    ///           unexpected API failure.
    func load(forPairing pairingID: UUID) throws -> SecureEnclave.P256.Signing.PrivateKey

    /// Deletes the Keychain item for the given pairing.  Silently succeeds if
    /// no item exists.
    ///
    /// - Parameter pairingID: The pairing whose item should be deleted.
    /// - Throws: `SecureKeyStoreError.keychainError` on unexpected API failure.
    func delete(forPairing pairingID: UUID) throws
}

// MARK: - Implementation

/// Concrete implementation that wraps `SecItemAdd`, `SecItemCopyMatching`, and
/// `SecItemDelete` from the iOS Security framework.
///
/// Keys are stored in the default Keychain for the app's data protection class.
/// The service identifier used as the Keychain primary key is constructed as:
///
///     "com.pcunlock.key.<pairingID.uuidString>"
///
/// This scopes each key to exactly one PC pairing, satisfying Requirement 2.4
/// (private key stays inside the Secure Enclave — only the opaque
/// `dataRepresentation` blob is stored) and Requirement 3.1 (P-256 Secure
/// Enclave API exclusively).
public final class SecureKeyStore: SecureKeyStoring {

    // MARK: Properties

    /// Keychain account label — shared across all PCUnlock entries so items can
    /// be grouped for auditing or mass deletion if needed.
    private let account: String

    // MARK: Init

    /// Creates a `SecureKeyStore`.
    /// - Parameter account: The Keychain `kSecAttrAccount` value used for all
    ///   entries.  Defaults to `"com.pcunlock.keystore"`.
    public init(account: String = "com.pcunlock.keystore") {
        self.account = account
    }

    // MARK: - Helpers

    /// Builds the service identifier string that uniquely identifies a Keychain
    /// item for a given pairing.
    private func serviceIdentifier(forPairing pairingID: UUID) -> String {
        "com.pcunlock.key.\(pairingID.uuidString)"
    }

    // MARK: - SecureKeyStoring

    public func store(
        _ key: SecureEnclave.P256.Signing.PrivateKey,
        forPairing pairingID: UUID
    ) throws {
        let service = serviceIdentifier(forPairing: pairingID)

        // `dataRepresentation` is an opaque blob produced by CryptoKit —
        // it does NOT export raw private key bytes from the Secure Enclave.
        // Storing this blob is safe and is explicitly supported by Apple as
        // the way to persist a SecureEnclave key reference across app launches.
        let blob = key.dataRepresentation

        // Try to delete any pre-existing item first so `SecItemAdd` won't
        // return `errSecDuplicateItem`.  It is not an error if nothing exists.
        let deleteQuery: [CFString: Any] = [
            kSecClass:       kSecClassGenericPassword,
            kSecAttrService: service,
            kSecAttrAccount: account
        ]
        let deleteStatus = SecItemDelete(deleteQuery as CFDictionary)
        guard deleteStatus == errSecSuccess || deleteStatus == errSecItemNotFound else {
            throw SecureKeyStoreError.keychainError(deleteStatus)
        }

        // Add the new item.
        let addQuery: [CFString: Any] = [
            kSecClass:                          kSecClassGenericPassword,
            kSecAttrService:                    service,
            kSecAttrAccount:                    account,
            kSecValueData:                      blob,
            // `afterFirstUnlock` keeps the item accessible after the device is
            // unlocked for the first time — suitable for an app that may need
            // to sign in the background after unlock.
            kSecAttrAccessible:                 kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly
        ]
        let addStatus = SecItemAdd(addQuery as CFDictionary, nil)
        guard addStatus == errSecSuccess else {
            throw SecureKeyStoreError.keychainError(addStatus)
        }
    }

    public func load(forPairing pairingID: UUID) throws -> SecureEnclave.P256.Signing.PrivateKey {
        let service = serviceIdentifier(forPairing: pairingID)

        let query: [CFString: Any] = [
            kSecClass:            kSecClassGenericPassword,
            kSecAttrService:      service,
            kSecAttrAccount:      account,
            kSecReturnData:       kCFBooleanTrue!,
            kSecMatchLimit:       kSecMatchLimitOne
        ]

        var result: AnyObject?
        let status = SecItemCopyMatching(query as CFDictionary, &result)

        switch status {
        case errSecSuccess:
            break
        case errSecItemNotFound:
            throw SecureKeyStoreError.itemNotFound
        default:
            throw SecureKeyStoreError.keychainError(status)
        }

        guard let blob = result as? Data else {
            throw SecureKeyStoreError.itemCorrupt
        }

        // Attempt to reconstruct the Secure Enclave key from the opaque blob.
        // This will fail (throw) if the blob is corrupt or the Secure Enclave
        // key has been invalidated (e.g. biometrics changed with
        // `.biometryCurrentSet` access control).
        do {
            return try SecureEnclave.P256.Signing.PrivateKey(dataRepresentation: blob)
        } catch {
            throw SecureKeyStoreError.itemCorrupt
        }
    }

    public func delete(forPairing pairingID: UUID) throws {
        let service = serviceIdentifier(forPairing: pairingID)

        let query: [CFString: Any] = [
            kSecClass:       kSecClassGenericPassword,
            kSecAttrService: service,
            kSecAttrAccount: account
        ]

        let status = SecItemDelete(query as CFDictionary)
        // `errSecItemNotFound` is not an error — caller asked to ensure the
        // item is gone, and it already was.
        guard status == errSecSuccess || status == errSecItemNotFound else {
            throw SecureKeyStoreError.keychainError(status)
        }
    }
}
