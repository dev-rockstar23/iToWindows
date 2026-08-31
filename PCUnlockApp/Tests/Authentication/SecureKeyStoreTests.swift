// Feature: pc-unlock
// Unit tests for SecureKeyStore.
// Requirements: 2.4, 2.5, 3.1

import XCTest
import CryptoKit
@testable import PCUnlockApp

// MARK: - Mock SecureKeyStore

/// In-memory substitute for the Keychain so tests run on any machine
/// (including CI) without requiring a real iOS Keychain.
///
/// We test the real SecureKeyStore in an integration test target that runs on
/// a physical device or simulator; this mock validates the protocol contract.
final class MockSecureKeyStore: SecureKeyStoring {

    // Backing store: serviceID → opaque blob
    private var storage: [String: Data] = [:]

    private func key(forPairing id: UUID) -> String {
        "com.pcunlock.key.\(id.uuidString)"
    }

    func store(
        _ key: SecureEnclave.P256.Signing.PrivateKey,
        forPairing pairingID: UUID
    ) throws {
        storage[self.key(forPairing: pairingID)] = key.dataRepresentation
    }

    func load(forPairing pairingID: UUID) throws -> SecureEnclave.P256.Signing.PrivateKey {
        guard let blob = storage[key(forPairing: pairingID)] else {
            throw SecureKeyStoreError.itemNotFound
        }
        do {
            return try SecureEnclave.P256.Signing.PrivateKey(dataRepresentation: blob)
        } catch {
            throw SecureKeyStoreError.itemCorrupt
        }
    }

    func delete(forPairing pairingID: UUID) throws {
        storage.removeValue(forKey: key(forPairing: pairingID))
        // No-op if absent — matches the production behaviour.
    }

    // Test helper: inject a corrupt blob to simulate a damaged Keychain entry.
    func injectCorruptBlob(forPairing pairingID: UUID) {
        storage[key(forPairing: pairingID)] = Data([0xDE, 0xAD, 0xBE, 0xEF])
    }

    // Test helper: check whether an item is present without going through load().
    func hasItem(forPairing pairingID: UUID) -> Bool {
        storage[key(forPairing: pairingID)] != nil
    }
}

// MARK: - Tests

/// These tests exercise the `SecureKeyStoring` protocol contract using the
/// `MockSecureKeyStore`.  They run on any platform.
///
/// Tests that require a real Secure Enclave key (i.e. must run on a simulator
/// or device) are placed in `SecureKeyStoreIntegrationTests.swift` and are
/// gated with `#if canImport(UIKit)`.
final class SecureKeyStoreTests: XCTestCase {

    // MARK: store / load round-trip

    /// Storing a key and then loading it for the same pairing should succeed
    /// and return an equivalent key (same public key bytes).
    func testStoreAndLoad_succeeds() throws {
        // Guard: Secure Enclave is only available on real Apple hardware.
        guard SecureEnclave.isAvailable else {
            throw XCTSkip("Secure Enclave not available on this machine")
        }

        let store = MockSecureKeyStore()
        let pairingID = UUID()

        let originalKey = try SecureEnclave.P256.Signing.PrivateKey()
        try store.store(originalKey, forPairing: pairingID)

        let loadedKey = try store.load(forPairing: pairingID)

        // Public keys must match — the private key material stays in the SE.
        XCTAssertEqual(
            originalKey.publicKey.rawRepresentation,
            loadedKey.publicKey.rawRepresentation,
            "Loaded key public component must match the stored key"
        )
    }

    // MARK: load — missing item

    /// Loading a key that was never stored should throw `itemNotFound`.
    func testLoad_missingItem_throwsItemNotFound() {
        let store = MockSecureKeyStore()
        let pairingID = UUID()

        XCTAssertThrowsError(try store.load(forPairing: pairingID)) { error in
            XCTAssertEqual(error as? SecureKeyStoreError, .itemNotFound)
        }
    }

    // MARK: load — corrupt item

    /// Loading a Keychain entry whose blob is garbage should throw `itemCorrupt`.
    func testLoad_corruptItem_throwsItemCorrupt() {
        let store = MockSecureKeyStore()
        let pairingID = UUID()

        store.injectCorruptBlob(forPairing: pairingID)

        XCTAssertThrowsError(try store.load(forPairing: pairingID)) { error in
            XCTAssertEqual(error as? SecureKeyStoreError, .itemCorrupt)
        }
    }

    // MARK: delete

    /// Deleting an existing item should make subsequent loads throw `itemNotFound`.
    func testDelete_existingItem_removesIt() throws {
        guard SecureEnclave.isAvailable else {
            throw XCTSkip("Secure Enclave not available on this machine")
        }

        let store = MockSecureKeyStore()
        let pairingID = UUID()

        let key = try SecureEnclave.P256.Signing.PrivateKey()
        try store.store(key, forPairing: pairingID)
        XCTAssertTrue(store.hasItem(forPairing: pairingID))

        try store.delete(forPairing: pairingID)
        XCTAssertFalse(store.hasItem(forPairing: pairingID))

        XCTAssertThrowsError(try store.load(forPairing: pairingID)) { error in
            XCTAssertEqual(error as? SecureKeyStoreError, .itemNotFound)
        }
    }

    /// Deleting an item that doesn't exist should not throw — idempotent.
    func testDelete_missingItem_noThrow() {
        let store = MockSecureKeyStore()
        let pairingID = UUID()

        XCTAssertNoThrow(try store.delete(forPairing: pairingID))
    }

    // MARK: pairing isolation

    /// Keys stored for different pairings must be completely independent.
    func testPairingIsolation() throws {
        guard SecureEnclave.isAvailable else {
            throw XCTSkip("Secure Enclave not available on this machine")
        }

        let store = MockSecureKeyStore()
        let pairingA = UUID()
        let pairingB = UUID()

        let keyA = try SecureEnclave.P256.Signing.PrivateKey()
        let keyB = try SecureEnclave.P256.Signing.PrivateKey()

        try store.store(keyA, forPairing: pairingA)
        try store.store(keyB, forPairing: pairingB)

        let loadedA = try store.load(forPairing: pairingA)
        let loadedB = try store.load(forPairing: pairingB)

        XCTAssertEqual(
            loadedA.publicKey.rawRepresentation,
            keyA.publicKey.rawRepresentation
        )
        XCTAssertEqual(
            loadedB.publicKey.rawRepresentation,
            keyB.publicKey.rawRepresentation
        )
        // Cross-check: the two public keys must differ.
        XCTAssertNotEqual(
            loadedA.publicKey.rawRepresentation,
            loadedB.publicKey.rawRepresentation
        )
    }

    // MARK: store overwrites previous entry (Requirement 3.7 enabler)

    /// Storing a new key for the same pairing should replace the previous one.
    /// This is the atomicity contract that `KeyManager.generateKeyPair` relies on.
    func testStore_overwritesPreviousEntry() throws {
        guard SecureEnclave.isAvailable else {
            throw XCTSkip("Secure Enclave not available on this machine")
        }

        let store = MockSecureKeyStore()
        let pairingID = UUID()

        let firstKey = try SecureEnclave.P256.Signing.PrivateKey()
        try store.store(firstKey, forPairing: pairingID)

        let secondKey = try SecureEnclave.P256.Signing.PrivateKey()
        try store.store(secondKey, forPairing: pairingID)

        let loadedKey = try store.load(forPairing: pairingID)
        XCTAssertEqual(
            loadedKey.publicKey.rawRepresentation,
            secondKey.publicKey.rawRepresentation,
            "load() should return the most-recently stored key"
        )
        XCTAssertNotEqual(
            loadedKey.publicKey.rawRepresentation,
            firstKey.publicKey.rawRepresentation,
            "The first key should have been replaced"
        )
    }

    // MARK: delete only removes target pairing

    /// Deleting pairing A must leave pairing B's key intact.
    func testDelete_onlyRemovesTargetPairing() throws {
        guard SecureEnclave.isAvailable else {
            throw XCTSkip("Secure Enclave not available on this machine")
        }

        let store = MockSecureKeyStore()
        let pairingA = UUID()
        let pairingB = UUID()

        let keyA = try SecureEnclave.P256.Signing.PrivateKey()
        let keyB = try SecureEnclave.P256.Signing.PrivateKey()

        try store.store(keyA, forPairing: pairingA)
        try store.store(keyB, forPairing: pairingB)

        try store.delete(forPairing: pairingA)

        XCTAssertFalse(store.hasItem(forPairing: pairingA))
        XCTAssertTrue(store.hasItem(forPairing: pairingB))

        let loadedB = try store.load(forPairing: pairingB)
        XCTAssertEqual(
            loadedB.publicKey.rawRepresentation,
            keyB.publicKey.rawRepresentation,
            "Pairing B's key should be unaffected by deleting Pairing A"
        )
    }
}
