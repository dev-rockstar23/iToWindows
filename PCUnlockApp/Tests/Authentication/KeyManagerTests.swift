// Feature: pc-unlock
// Unit tests for KeyManager.
// Requirements: 2.4, 2.5, 3.1, 3.7

import XCTest
import CryptoKit
@testable import PCUnlockApp

// MARK: - SpySecureKeyStore

/// A `SecureKeyStoring` implementation that additionally records the *sequence*
/// of calls made against it.  This lets tests assert that `delete` was called
/// before `store` during `generateKeyPair` (Requirement 3.7).
final class SpySecureKeyStore: SecureKeyStoring {

    // MARK: Call record

    enum Call: Equatable {
        case store(pairingID: UUID)
        case load(pairingID: UUID)
        case delete(pairingID: UUID)
    }

    private(set) var calls: [Call] = []

    // MARK: Backing store

    private var storage: [UUID: Data] = [:]

    // MARK: Optional fault injection

    /// When non-nil, `store` throws this error instead of succeeding.
    var storeError: Error?
    /// When non-nil, `load` throws this error instead of succeeding.
    var loadError: Error?
    /// When non-nil, `delete` throws this error instead of succeeding.
    var deleteError: Error?

    // MARK: SecureKeyStoring

    func store(
        _ key: SecureEnclave.P256.Signing.PrivateKey,
        forPairing pairingID: UUID
    ) throws {
        calls.append(.store(pairingID: pairingID))
        if let error = storeError { throw error }
        storage[pairingID] = key.dataRepresentation
    }

    func load(forPairing pairingID: UUID) throws -> SecureEnclave.P256.Signing.PrivateKey {
        calls.append(.load(pairingID: pairingID))
        if let error = loadError { throw error }
        guard let blob = storage[pairingID] else {
            throw SecureKeyStoreError.itemNotFound
        }
        do {
            return try SecureEnclave.P256.Signing.PrivateKey(dataRepresentation: blob)
        } catch {
            throw SecureKeyStoreError.itemCorrupt
        }
    }

    func delete(forPairing pairingID: UUID) throws {
        calls.append(.delete(pairingID: pairingID))
        if let error = deleteError { throw error }
        storage.removeValue(forKey: pairingID)
    }

    // MARK: Helpers

    func hasItem(forPairing pairingID: UUID) -> Bool {
        storage[pairingID] != nil
    }
}

// MARK: - Tests

final class KeyManagerTests: XCTestCase {

    // MARK: - generateKeyPair: delete-before-generate ordering (Requirement 3.7)

    /// `generateKeyPair` must call `delete` before `store` so that any
    /// previously stored key is removed atomically before the new one is
    /// created.
    func testGenerateKeyPair_deletesExistingKeyBeforeGeneratingNewOne() throws {
        guard SecureEnclave.isAvailable else {
            throw XCTSkip("Secure Enclave not available on this machine")
        }

        let spy = SpySecureKeyStore()
        let manager = KeyManager(secureKeyStore: spy)
        let pairingID = UUID()

        _ = try manager.generateKeyPair(forPairing: pairingID)

        // We expect exactly: delete → store
        XCTAssertEqual(spy.calls.count, 2,
            "generateKeyPair should call delete then store — exactly 2 operations")
        XCTAssertEqual(spy.calls[0], .delete(pairingID: pairingID),
            "First operation must be delete (Requirement 3.7)")
        XCTAssertEqual(spy.calls[1], .store(pairingID: pairingID),
            "Second operation must be store")
    }

    /// Calling `generateKeyPair` twice for the same pairing must delete the
    /// previous key on each call before creating the new one.
    func testGenerateKeyPair_calledTwice_deletesOldKeyEachTime() throws {
        guard SecureEnclave.isAvailable else {
            throw XCTSkip("Secure Enclave not available on this machine")
        }

        let spy = SpySecureKeyStore()
        let manager = KeyManager(secureKeyStore: spy)
        let pairingID = UUID()

        _ = try manager.generateKeyPair(forPairing: pairingID)
        _ = try manager.generateKeyPair(forPairing: pairingID)

        // Expected sequence: delete, store, delete, store
        let expected: [SpySecureKeyStore.Call] = [
            .delete(pairingID: pairingID),
            .store(pairingID: pairingID),
            .delete(pairingID: pairingID),
            .store(pairingID: pairingID)
        ]
        XCTAssertEqual(spy.calls, expected,
            "Each generateKeyPair call must delete before storing (Requirement 3.7)")
    }

    // MARK: - generateKeyPair: key is stored and is different on each call

    /// After `generateKeyPair`, the key should be findable via `loadPrivateKey`.
    func testGenerateKeyPair_storesKeyLoadable() throws {
        guard SecureEnclave.isAvailable else {
            throw XCTSkip("Secure Enclave not available on this machine")
        }

        let store = MockSecureKeyStore()
        let manager = KeyManager(secureKeyStore: store)
        let pairingID = UUID()

        let publicKey = try manager.generateKeyPair(forPairing: pairingID)
        let loadedPrivate = try manager.loadPrivateKey(forPairing: pairingID)

        XCTAssertEqual(
            loadedPrivate.publicKey.rawRepresentation,
            publicKey.rawRepresentation,
            "The public key returned by generateKeyPair must match the public component of the stored private key"
        )
    }

    /// Each call to `generateKeyPair` for the same pairing produces a *new*
    /// key pair — the public key must differ.
    func testGenerateKeyPair_producesNewKeyOnEachCall() throws {
        guard SecureEnclave.isAvailable else {
            throw XCTSkip("Secure Enclave not available on this machine")
        }

        let store = MockSecureKeyStore()
        let manager = KeyManager(secureKeyStore: store)
        let pairingID = UUID()

        let firstPublic = try manager.generateKeyPair(forPairing: pairingID)
        let secondPublic = try manager.generateKeyPair(forPairing: pairingID)

        XCTAssertNotEqual(
            firstPublic.rawRepresentation,
            secondPublic.rawRepresentation,
            "Successive key generations for the same pairing must produce distinct key pairs"
        )
    }

    // MARK: - generateKeyPair: old key absent after regeneration (Property 6 enabler)

    /// After regeneration, only the *new* key is accessible.  The old key
    /// reference must be absent from the store (Requirement 3.7, Property 6).
    func testGenerateKeyPair_oldKeyAbsentAfterRegeneration() throws {
        guard SecureEnclave.isAvailable else {
            throw XCTSkip("Secure Enclave not available on this machine")
        }

        let store = MockSecureKeyStore()
        let manager = KeyManager(secureKeyStore: store)
        let pairingID = UUID()

        let firstPublic = try manager.generateKeyPair(forPairing: pairingID)
        let secondPublic = try manager.generateKeyPair(forPairing: pairingID)

        // Only the new key should be present.
        let loaded = try manager.loadPrivateKey(forPairing: pairingID)
        XCTAssertEqual(
            loaded.publicKey.rawRepresentation,
            secondPublic.rawRepresentation,
            "loadPrivateKey must return the most recently generated key"
        )
        XCTAssertNotEqual(
            loaded.publicKey.rawRepresentation,
            firstPublic.rawRepresentation,
            "The first key must have been replaced — it should not be loadable"
        )
    }

    // MARK: - generateKeyPair: pairing isolation

    /// Generating a key pair for one pairing must not disturb keys stored for
    /// other pairings.
    func testGenerateKeyPair_doesNotAffectOtherPairings() throws {
        guard SecureEnclave.isAvailable else {
            throw XCTSkip("Secure Enclave not available on this machine")
        }

        let store = MockSecureKeyStore()
        let manager = KeyManager(secureKeyStore: store)
        let pairingA = UUID()
        let pairingB = UUID()

        let publicA = try manager.generateKeyPair(forPairing: pairingA)
        _ = try manager.generateKeyPair(forPairing: pairingB)

        // Re-generate only pairing B; pairing A's key must be unchanged.
        _ = try manager.generateKeyPair(forPairing: pairingB)

        let loadedA = try manager.loadPrivateKey(forPairing: pairingA)
        XCTAssertEqual(
            loadedA.publicKey.rawRepresentation,
            publicA.rawRepresentation,
            "Key regeneration for Pairing B must not affect Pairing A's stored key"
        )
    }

    // MARK: - loadPrivateKey

    /// Loading a key for a pairing that has never had a key stored must
    /// propagate `SecureKeyStoreError.itemNotFound`.
    func testLoadPrivateKey_missingKey_throwsItemNotFound() {
        let store = MockSecureKeyStore()
        let manager = KeyManager(secureKeyStore: store)
        let pairingID = UUID()

        XCTAssertThrowsError(try manager.loadPrivateKey(forPairing: pairingID)) { error in
            XCTAssertEqual(error as? SecureKeyStoreError, .itemNotFound)
        }
    }

    /// A corrupt blob stored in the keychain must propagate
    /// `SecureKeyStoreError.itemCorrupt`.
    func testLoadPrivateKey_corruptBlob_throwsItemCorrupt() {
        let store = MockSecureKeyStore()
        let manager = KeyManager(secureKeyStore: store)
        let pairingID = UUID()

        store.injectCorruptBlob(forPairing: pairingID)

        XCTAssertThrowsError(try manager.loadPrivateKey(forPairing: pairingID)) { error in
            XCTAssertEqual(error as? SecureKeyStoreError, .itemCorrupt)
        }
    }

    // MARK: - deleteKeyPair

    /// After `deleteKeyPair`, `loadPrivateKey` must throw `itemNotFound`.
    func testDeleteKeyPair_removesStoredKey() throws {
        guard SecureEnclave.isAvailable else {
            throw XCTSkip("Secure Enclave not available on this machine")
        }

        let store = MockSecureKeyStore()
        let manager = KeyManager(secureKeyStore: store)
        let pairingID = UUID()

        _ = try manager.generateKeyPair(forPairing: pairingID)
        XCTAssertTrue(store.hasItem(forPairing: pairingID),
            "Key should be present after generation")

        try manager.deleteKeyPair(forPairing: pairingID)
        XCTAssertFalse(store.hasItem(forPairing: pairingID),
            "Key should be absent after deletion")

        XCTAssertThrowsError(try manager.loadPrivateKey(forPairing: pairingID)) { error in
            XCTAssertEqual(error as? SecureKeyStoreError, .itemNotFound)
        }
    }

    /// `deleteKeyPair` on a pairing with no stored key must not throw (idempotent).
    func testDeleteKeyPair_missingKey_noThrow() {
        let store = MockSecureKeyStore()
        let manager = KeyManager(secureKeyStore: store)
        let pairingID = UUID()

        XCTAssertNoThrow(try manager.deleteKeyPair(forPairing: pairingID))
    }

    /// Deleting a key for one pairing must leave other pairings' keys intact.
    func testDeleteKeyPair_onlyRemovesTargetPairing() throws {
        guard SecureEnclave.isAvailable else {
            throw XCTSkip("Secure Enclave not available on this machine")
        }

        let store = MockSecureKeyStore()
        let manager = KeyManager(secureKeyStore: store)
        let pairingA = UUID()
        let pairingB = UUID()

        _ = try manager.generateKeyPair(forPairing: pairingA)
        let publicB = try manager.generateKeyPair(forPairing: pairingB)

        try manager.deleteKeyPair(forPairing: pairingA)

        XCTAssertFalse(store.hasItem(forPairing: pairingA),
            "Pairing A's key must be removed")
        XCTAssertTrue(store.hasItem(forPairing: pairingB),
            "Pairing B's key must be unaffected")

        let loadedB = try manager.loadPrivateKey(forPairing: pairingB)
        XCTAssertEqual(
            loadedB.publicKey.rawRepresentation,
            publicB.rawRepresentation,
            "Pairing B's key content must be unchanged after Pairing A's deletion"
        )
    }

    // MARK: - secureEnclaveUnavailable guard

    /// When `SecureEnclave.isAvailable` is false, `generateKeyPair` must throw
    /// `KeyManagerError.secureEnclaveUnavailable` rather than silently using a
    /// software key (Requirement 3.1).
    ///
    /// NOTE: This test is skipped when the Secure Enclave IS available, because
    /// we cannot mock `SecureEnclave.isAvailable` without a simulator override.
    /// The real enforcement is validated by code inspection of `KeyManager`.
    func testGenerateKeyPair_secureEnclaveUnavailable_isHandled() throws {
        // On hardware with SE, document the expected behaviour via assertion on
        // the code path that runs; we can't force SE unavailability here.
        //
        // On CI / macOS without SE, the guard will fire and we validate it.
        if SecureEnclave.isAvailable {
            // SE is available — confirm generateKeyPair succeeds normally.
            let store = MockSecureKeyStore()
            let manager = KeyManager(secureKeyStore: store)
            XCTAssertNoThrow(try manager.generateKeyPair(forPairing: UUID()),
                "generateKeyPair should succeed when Secure Enclave is available")
        } else {
            // SE is not available — confirm the guard throws.
            let store = MockSecureKeyStore()
            let manager = KeyManager(secureKeyStore: store)
            XCTAssertThrowsError(try manager.generateKeyPair(forPairing: UUID())) { error in
                XCTAssertEqual(error as? KeyManagerError, .secureEnclaveUnavailable,
                    "generateKeyPair must throw .secureEnclaveUnavailable when SE is not present")
            }
        }
    }
}
