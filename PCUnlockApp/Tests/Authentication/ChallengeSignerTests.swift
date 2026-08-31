// Feature: pc-unlock
// ChallengeSignerTests — unit tests for `ChallengeSigner`, `Response`, and
// `Challenge.init(from:)` wire-format decoding.
// Requirements: 2.1, 2.2, 2.3, 2.4, 3.1, 3.6

import XCTest
import CryptoKit
import LocalAuthentication
@testable import PCUnlockApp

// MARK: - Mock FaceIDManaging implementations

/// A `FaceIDManaging` stub that always returns `.success`.
private final class SucceedingFaceIDManager: FaceIDManaging {
    func authenticate(reason: String) async -> Result<Void, LAError> {
        return .success(())
    }
}

/// A `FaceIDManaging` stub that always returns the specified `LAError`.
private final class FailingFaceIDManager: FaceIDManaging {
    private let error: LAError

    init(code: LAError.Code = .authenticationFailed) {
        self.error = LAError(code)
    }

    func authenticate(reason: String) async -> Result<Void, LAError> {
        return .failure(error)
    }
}

// MARK: - Helpers

/// Builds a valid 57-byte canonical challenge wire payload.
///
/// - Parameters:
///   - version:   1-byte protocol version.
///   - sessionId: 16-byte UUID.
///   - nonce:     Exactly 32 bytes.
///   - expiresAt: Unix epoch seconds (Int64, little-endian).
private func makeWireBytes(
    version: UInt8 = 1,
    sessionId: UUID = UUID(),
    nonce: Data = Data(repeating: 0xAB, count: 32),
    expiresAt: Int64
) -> Data {
    var data = Data()
    data.reserveCapacity(57)

    // version (1 byte)
    data.append(version)

    // sessionId (16 bytes, UUID big-endian wire format)
    let (u1, u2, u3, u4, u5, u6, u7, u8,
         u9, u10, u11, u12, u13, u14, u15, u16) = sessionId.uuid
    data.append(contentsOf: [
        u1, u2, u3, u4, u5, u6, u7, u8,
        u9, u10, u11, u12, u13, u14, u15, u16
    ])

    // nonce (32 bytes)
    data.append(nonce)

    // expiresAt (8 bytes, little-endian int64)
    var le = expiresAt.littleEndian
    withUnsafeBytes(of: &le) { data.append(contentsOf: $0) }

    return data
}

/// Runs an async `sign(...)` call synchronously via a semaphore so it can be
/// used from a synchronous XCTest method.
private func runSign(
    challenge: Challenge,
    signer: ChallengeSigner,
    key: SecureEnclave.P256.Signing.PrivateKey,
    deviceId: UUID = UUID()
) -> (Response?, Error?) {
    var response: Response?
    var thrown: Error?
    let sem = DispatchSemaphore(value: 0)
    Task {
        do {
            response = try await signer.sign(
                challenge: challenge,
                deviceId: deviceId,
                usingKey: key
            )
        } catch {
            thrown = error
        }
        sem.signal()
    }
    sem.wait()
    return (response, thrown)
}

// MARK: - ChallengeSignerTests

final class ChallengeSignerTests: XCTestCase {

    // MARK: - Wire-format decode: valid bytes

    /// Decoding a correctly formed 57-byte payload must succeed and round-trip
    /// all fields correctly.
    func testDecode_validBytes_roundTripsAllFields() throws {
        let expectedVersion: UInt8 = 1
        let expectedSessionId = UUID()
        let expectedNonce = Data((0..<32).map { UInt8($0) })
        // 60 seconds in the future
        let expectedExpiresAt = Int64(Date().timeIntervalSince1970) + 60

        let bytes = makeWireBytes(
            version: expectedVersion,
            sessionId: expectedSessionId,
            nonce: expectedNonce,
            expiresAt: expectedExpiresAt
        )

        XCTAssertEqual(bytes.count, 57, "Wire bytes must be exactly 57 bytes")

        let challenge = try Challenge(from: bytes)

        XCTAssertEqual(challenge.version, expectedVersion)
        XCTAssertEqual(challenge.sessionId, expectedSessionId)
        XCTAssertEqual(challenge.nonce, expectedNonce)
        XCTAssertEqual(challenge.expiresAt, expectedExpiresAt)
    }

    /// Decoding with version=0 must still succeed — version is opaque data and
    /// not validated during decoding.
    func testDecode_versionZero_succeeds() throws {
        let expiresAt = Int64(Date().timeIntervalSince1970) + 120
        let bytes = makeWireBytes(version: 0, expiresAt: expiresAt)
        let challenge = try Challenge(from: bytes)
        XCTAssertEqual(challenge.version, 0)
    }

    // MARK: - Wire-format decode: length errors

    /// Buffers shorter than 57 bytes must throw `invalidLength`.
    func testDecode_tooFewBytes_throwsInvalidLength() {
        let bytes = Data(repeating: 0x00, count: 56)
        XCTAssertThrowsError(try Challenge(from: bytes)) { error in
            XCTAssertEqual(error as? ChallengeDecodingError,
                           .invalidLength(56))
        }
    }

    /// Buffers longer than 57 bytes must throw `invalidLength`.
    func testDecode_tooManyBytes_throwsInvalidLength() {
        let bytes = Data(repeating: 0x00, count: 58)
        XCTAssertThrowsError(try Challenge(from: bytes)) { error in
            XCTAssertEqual(error as? ChallengeDecodingError,
                           .invalidLength(58))
        }
    }

    /// An empty buffer must throw `invalidLength(0)`.
    func testDecode_emptyBytes_throwsInvalidLength() {
        XCTAssertThrowsError(try Challenge(from: Data())) { error in
            XCTAssertEqual(error as? ChallengeDecodingError,
                           .invalidLength(0))
        }
    }

    // MARK: - Wire-format decode: expiry validation

    /// A challenge whose `expiresAt` is in the past must throw
    /// `ChallengeDecodingError.challengeExpired`.
    func testDecode_expiredChallenge_throwsChallengeExpired() {
        let past = Int64(Date().timeIntervalSince1970) - 1
        let bytes = makeWireBytes(expiresAt: past)
        XCTAssertThrowsError(try Challenge(from: bytes)) { error in
            XCTAssertEqual(error as? ChallengeDecodingError, .challengeExpired)
        }
    }

    /// A challenge expiring at exactly `now` must also be rejected (not strictly
    /// in the future).
    func testDecode_expiresAtExactlyNow_throwsChallengeExpired() {
        let now = Int64(Date().timeIntervalSince1970)
        let bytes = makeWireBytes(expiresAt: now)
        XCTAssertThrowsError(try Challenge(from: bytes)) { error in
            XCTAssertEqual(error as? ChallengeDecodingError, .challengeExpired)
        }
    }

    /// A challenge expiring 1 second in the future must decode successfully.
    func testDecode_expiresOneSecondInFuture_succeeds() throws {
        let soon = Int64(Date().timeIntervalSince1970) + 1
        let bytes = makeWireBytes(expiresAt: soon)
        XCTAssertNoThrow(try Challenge(from: bytes))
    }

    // MARK: - ChallengeSigner: expiry rejection (no SE required)

    /// A `Challenge` whose `expiresAt` is in the past must be rejected before
    /// Face ID is called — `ChallengeSignerError.challengeExpired` should be
    /// thrown even with a succeeding Face ID mock.
    ///
    /// Because the expiry check happens before the SE signing step, we can use
    /// a software key here if SE is unavailable; however we still guard it
    /// and skip rather than fail if we cannot create any key at all.
    ///
    /// **Validates: Requirements 2.2, 2.3**
    func testSign_expiredChallenge_throwsChallengeExpired() throws {
        // Build an already-expired challenge directly (bypass init(from:) which
        // would also throw — we want to get an instance into the signer).
        let past = Int64(Date().timeIntervalSince1970) - 10
        let challenge = Challenge(
            version: 1,
            sessionId: UUID(),
            nonce: Data(repeating: 0x01, count: 32),
            expiresAt: past
        )

        guard SecureEnclave.isAvailable else {
            throw XCTSkip("Secure Enclave not available on this device")
        }
        let key = try SecureEnclave.P256.Signing.PrivateKey()

        let signer = ChallengeSigner(faceIDManager: SucceedingFaceIDManager())
        let (response, error) = runSign(challenge: challenge, signer: signer, key: key)

        XCTAssertNil(response, "Must not produce a Response for an expired challenge")
        XCTAssertEqual(error as? ChallengeSignerError, .challengeExpired)
    }

    // MARK: - ChallengeSigner: Face ID failure rejection

    /// When `FaceIDManaging.authenticate` returns `.failure`, `ChallengeSigner`
    /// must throw `authenticationFailed` and produce no Response.
    ///
    /// **Validates: Requirements 2.1, 2.2**
    func testSign_faceIDFailure_throwsAuthenticationFailed() throws {
        guard SecureEnclave.isAvailable else {
            throw XCTSkip("Secure Enclave not available on this device")
        }

        let key = try SecureEnclave.P256.Signing.PrivateKey()
        let future = Int64(Date().timeIntervalSince1970) + 60
        let challenge = Challenge(
            version: 1,
            sessionId: UUID(),
            nonce: Data(repeating: 0xCC, count: 32),
            expiresAt: future
        )

        let signer = ChallengeSigner(faceIDManager: FailingFaceIDManager())
        let (response, error) = runSign(challenge: challenge, signer: signer, key: key)

        XCTAssertNil(response, "No Response must be produced when Face ID fails")
        XCTAssertEqual(error as? ChallengeSignerError, .authenticationFailed)
    }

    /// Failure is independent of the specific `LAError.Code` — all error codes
    /// must result in `authenticationFailed`.
    ///
    /// **Validates: Requirements 2.1, 2.2**
    func testSign_allFaceIDErrorCodes_allThrowAuthenticationFailed() throws {
        guard SecureEnclave.isAvailable else {
            throw XCTSkip("Secure Enclave not available on this device")
        }

        let key = try SecureEnclave.P256.Signing.PrivateKey()
        let future = Int64(Date().timeIntervalSince1970) + 60
        let challenge = Challenge(
            version: 1,
            sessionId: UUID(),
            nonce: Data(repeating: 0xDD, count: 32),
            expiresAt: future
        )

        let failureCodes: [LAError.Code] = [
            .authenticationFailed,
            .userCancel,
            .userFallback,
            .systemCancel,
            .passcodeNotSet,
            .biometryNotAvailable,
            .biometryNotEnrolled,
            .biometryLockout,
            .appCancel,
            .invalidContext
        ]

        for code in failureCodes {
            let signer = ChallengeSigner(faceIDManager: FailingFaceIDManager(code: code))
            let (response, error) = runSign(challenge: challenge, signer: signer, key: key)

            XCTAssertNil(response,
                "No Response must be produced for LAError.Code \(code.rawValue)")
            XCTAssertEqual(error as? ChallengeSignerError, .authenticationFailed,
                "Must throw .authenticationFailed for LAError.Code \(code.rawValue)")
        }
    }

    // MARK: - ChallengeSigner: successful sign

    /// On success (Face ID passes, challenge not expired, valid SE key):
    ///   - `Response.sessionId` must match `challenge.sessionId`
    ///   - `Response.deviceId`  must match the `deviceId` passed to `sign`
    ///   - `Response.version`   must match `challenge.version`
    ///   - `Response.signatureDER` must be non-empty
    ///
    /// **Validates: Requirements 2.1, 2.3, 2.4, 3.1, 3.6**
    func testSign_success_returnsCorrectResponse() throws {
        guard SecureEnclave.isAvailable else {
            throw XCTSkip("Secure Enclave not available on this device")
        }

        let key = try SecureEnclave.P256.Signing.PrivateKey()
        let expectedSessionId = UUID()
        let expectedDeviceId  = UUID()
        let future = Int64(Date().timeIntervalSince1970) + 60

        let challenge = Challenge(
            version: 1,
            sessionId: expectedSessionId,
            nonce: Data(repeating: 0xFF, count: 32),
            expiresAt: future
        )

        let signer = ChallengeSigner(faceIDManager: SucceedingFaceIDManager())
        let (response, error) = runSign(
            challenge: challenge,
            signer: signer,
            key: key,
            deviceId: expectedDeviceId
        )

        XCTAssertNil(error, "No error expected on success: \(error!)")
        let r = try XCTUnwrap(response, "Response must not be nil on success")

        XCTAssertEqual(r.sessionId, expectedSessionId,
            "Response.sessionId must match the signed challenge's sessionId")
        XCTAssertEqual(r.deviceId, expectedDeviceId,
            "Response.deviceId must match the caller-supplied deviceId")
        XCTAssertEqual(r.version, 1,
            "Response.version must match challenge.version")
        XCTAssertFalse(r.signatureDER.isEmpty,
            "Response.signatureDER must not be empty")
    }

    /// The DER signature in the Response must be verifiable with the key's
    /// corresponding public key over `SHA256(challenge.canonicalBytes())`.
    ///
    /// This test validates the end-to-end crypto correctness of `ChallengeSigner`.
    ///
    /// **Validates: Requirements 3.1, 3.6**
    func testSign_success_signatureVerifiesWithPublicKey() throws {
        guard SecureEnclave.isAvailable else {
            throw XCTSkip("Secure Enclave not available on this device")
        }

        let key = try SecureEnclave.P256.Signing.PrivateKey()
        let publicKey = key.publicKey

        let future = Int64(Date().timeIntervalSince1970) + 60
        let challenge = Challenge(
            version: 1,
            sessionId: UUID(),
            nonce: Data((0..<32).map { UInt8($0 &* 3) }),
            expiresAt: future
        )

        let signer = ChallengeSigner(faceIDManager: SucceedingFaceIDManager())
        let (response, _) = runSign(challenge: challenge, signer: signer, key: key)
        let r = try XCTUnwrap(response)

        // Re-derive the digest the same way the signer does.
        let digest = SHA256.hash(data: challenge.canonicalBytes())

        // Parse the DER signature and verify.
        let parsedSignature = try P256.Signing.ECDSASignature(derRepresentation: r.signatureDER)
        XCTAssertTrue(
            publicKey.isValidSignature(parsedSignature, for: digest),
            "DER signature in Response must be valid for SHA256(canonicalBytes)"
        )
    }

    // MARK: - Response struct

    /// `Response` must round-trip all fields through its memberwise initialiser.
    func testResponse_memberwise_roundTrips() {
        let ver: UInt8 = 2
        let sid = UUID()
        let did = UUID()
        let sig = Data([0x30, 0x44, 0x02, 0x20])

        let r = Response(version: ver, sessionId: sid, deviceId: did, signatureDER: sig)

        XCTAssertEqual(r.version, ver)
        XCTAssertEqual(r.sessionId, sid)
        XCTAssertEqual(r.deviceId, did)
        XCTAssertEqual(r.signatureDER, sig)
    }

    /// Two `Response` values with identical fields must be equal.
    func testResponse_equality_identicalFields_areEqual() {
        let sid = UUID()
        let did = UUID()
        let sig = Data([0xAA, 0xBB])

        let r1 = Response(version: 1, sessionId: sid, deviceId: did, signatureDER: sig)
        let r2 = Response(version: 1, sessionId: sid, deviceId: did, signatureDER: sig)

        XCTAssertEqual(r1, r2)
    }

    /// Two `Response` values differing in `sessionId` must not be equal.
    func testResponse_equality_differentSessionId_notEqual() {
        let sig = Data([0x01])
        let r1 = Response(version: 1, sessionId: UUID(), deviceId: UUID(), signatureDER: sig)
        let r2 = Response(version: 1, sessionId: UUID(), deviceId: r1.deviceId, signatureDER: sig)
        XCTAssertNotEqual(r1, r2)
    }
}
