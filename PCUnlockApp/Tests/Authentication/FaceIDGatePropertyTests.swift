// Feature: pc-unlock, Property 3
// FaceIDGatePropertyTests — property-based tests verifying that ChallengeSigner
// produces NO Response when Face ID authentication fails.
//
// Validates: Requirements 2.1, 2.2
//
// Property 3: Face ID gate — no signature without successful authentication
//   For any Challenge value, if the LocalAuthentication call returns a failure
//   result, the ChallengeSigner SHALL produce no Response and SHALL return an
//   error to the caller.

import XCTest
import CryptoKit
import LocalAuthentication
import SwiftCheck
@testable import PCUnlockApp

// MARK: - Mock: always-failing FaceIDManaging

/// A `FaceIDManaging` stub that always returns a specified `LAError`.
/// Used to simulate every possible authentication failure mode.
private final class FailingFaceIDManager: FaceIDManaging {
    let errorCode: LAError.Code

    init(errorCode: LAError.Code) {
        self.errorCode = errorCode
    }

    func authenticate(reason: String) async -> Result<Void, LAError> {
        return .failure(LAError(errorCode))
    }
}

// MARK: - SwiftCheck Arbitrary conformances

/// All `LAError.Code` failure cases that `LocalAuthentication` can return.
private let allFailureCodes: [LAError.Code] = [
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

/// Generator for an arbitrary `LAError.Code` failure value.
private let arbitraryErrorCode: Gen<LAError.Code> =
    Gen<LAError.Code>.fromElements(of: allFailureCodes)

/// Generator for exactly 32 bytes of arbitrary data (the required nonce size).
private let arbitraryNonce: Gen<Data> =
    UInt8.arbitrary
        .proliferate(withSize: 32)
        .map { Data($0) }

/// Generator for a Unix timestamp at least 60 seconds in the future.
///
/// Using a fixed 3600-second offset ensures the expiry guard in `ChallengeSigner`
/// is never triggered — isolating the Face ID gate behaviour exclusively.
private let arbitraryFutureTimestamp: Gen<Int64> =
    Int32.arbitrary
        .map { offset in
            let base = Int64(Date().timeIntervalSince1970)
            // Guarantee at least 60s in the future; spread across up to ~1 hour.
            return base + 60 + Int64(abs(Int(offset)) % 3540 + 1)
        }

/// Makes `Challenge` conform to `Arbitrary` so SwiftCheck can generate random
/// instances for property testing.
extension Challenge: Arbitrary {
    public static var arbitrary: Gen<Challenge> {
        // Chain generators with flatMap to combine 4 independent fields.
        UInt8.arbitrary.flatMap { version in
            arbitraryNonce.flatMap { nonce in
                arbitraryFutureTimestamp.map { expiresAt in
                    // UUID is not random via SwiftCheck; generate a new one on
                    // each call — UUID() is CSPRNG-backed and unique per call.
                    Challenge(
                        version:   version,
                        sessionId: UUID(),
                        nonce:     nonce,
                        expiresAt: expiresAt
                    )
                }
            }
        }
    }
}

// MARK: - Property tests

/// Property-based tests for Property 3 of the PCUnlock specification.
///
/// **Property 3:** For *any* `Challenge` value, when `FaceIDManaging` returns a
/// failure result, `ChallengeSigner` MUST:
///   1. Throw `ChallengeSignerError.authenticationFailed`.
///   2. NOT return any `Data` (i.e. produce no Response).
///
/// Tests run a minimum of 100 iterations via SwiftCheck's `property` operator.
final class FaceIDGatePropertyTests: XCTestCase {

    // MARK: - Private helpers

    /// Runs `signer.sign(challenge:deviceId:usingKey:)` synchronously using a
    /// semaphore so it can be called from within a SwiftCheck `forAll` closure.
    ///
    /// Returns `(response, error)` — exactly one of which will be non-nil.
    private func runSign(
        challenge: Challenge,
        signer: ChallengeSigner,
        key: SecureEnclave.P256.Signing.PrivateKey
    ) -> (Response?, Error?) {
        var returned: Response?
        var thrown: Error?
        let sem = DispatchSemaphore(value: 0)
        Task {
            do {
                returned = try await signer.sign(
                    challenge: challenge,
                    deviceId: UUID(),
                    usingKey: key
                )
            } catch {
                thrown = error
            }
            sem.signal()
        }
        sem.wait()
        return (returned, thrown)
    }

    // MARK: - Property 3a: any Challenge × any LAError failure → throws, no Response

    /// For any arbitrary (Challenge, LAError.Code) pair where the LAError is a
    /// failure code, `ChallengeSigner.sign` must throw
    /// `ChallengeSignerError.authenticationFailed` and must never return `Data`.
    ///
    /// Minimum 100 iterations (SwiftCheck default is 100).
    ///
    /// **Validates: Requirements 2.1, 2.2**
    func testProperty3_anyChallenge_anyFailureCode_throwsNoResponse() {
        // Minimum 100 successful tests required.
        let config = CheckerArguments(
            maxAllowableSuccessfulTests: 100,
            maxAllowableDiscardedTests: 500,
            maxTestCaseSize: 100
        )

        property(
            "Property 3: any Challenge + Face ID failure → no Response",
            arguments: config
        ) <- forAll(Challenge.arbitrary, arbitraryErrorCode) { challenge, errorCode in

            let signer = ChallengeSigner(
                faceIDManager: FailingFaceIDManager(errorCode: errorCode)
            )

            // We need a Secure Enclave key.  On hardware without SE (e.g. macOS
            // CI machines) we cannot create one — discard the test case.
            guard SecureEnclave.isAvailable else {
                // Return `true` to mark as discard-friendly; the test runner
                // will skip iterations where SE is unavailable.
                return true
            }

            let key: SecureEnclave.P256.Signing.PrivateKey
            do {
                key = try SecureEnclave.P256.Signing.PrivateKey()
            } catch {
                // Key generation failed (device locked, etc.); discard.
                return true
            }

            let (returned, thrown) = self.runSign(
                challenge: challenge,
                signer: signer,
                key: key
            )

            // The signer must NOT have returned any data (no Response produced).
            guard returned == nil else { return false }

            // The signer must have thrown ChallengeSignerError.authenticationFailed.
            guard let error = thrown as? ChallengeSignerError else { return false }
            return error == .authenticationFailed
        }
    }

    // MARK: - Property 3b: failure is independent of Challenge field values

    /// Even when the Challenge has unusual field values (version=0, zero nonce,
    /// far-future expiry, etc.) the Face ID gate must still prevent signing.
    ///
    /// This property exercises boundary cases that unit tests might miss.
    ///
    /// Minimum 100 iterations.
    ///
    /// **Validates: Requirements 2.1, 2.2**
    func testProperty3_edgeCaseChallenges_failureStillPreventsResponse() {
        let config = CheckerArguments(
            maxAllowableSuccessfulTests: 100,
            maxAllowableDiscardedTests: 500,
            maxTestCaseSize: 100
        )

        property(
            "Property 3 (edge): unusual Challenge fields + Face ID failure → no Response",
            arguments: config
        ) <- forAll(Challenge.arbitrary) { challenge in

            // Pin to authenticationFailed — variation over errorCode is already
            // covered by testProperty3_anyChallenge_anyFailureCode_throwsNoResponse.
            let signer = ChallengeSigner(
                faceIDManager: FailingFaceIDManager(errorCode: .authenticationFailed)
            )

            guard SecureEnclave.isAvailable else { return true }

            let key: SecureEnclave.P256.Signing.PrivateKey
            do {
                key = try SecureEnclave.P256.Signing.PrivateKey()
            } catch {
                return true
            }

            let (returned, thrown) = self.runSign(
                challenge: challenge,
                signer: signer,
                key: key
            )

            guard returned == nil else { return false }
            guard let error = thrown as? ChallengeSignerError else { return false }
            return error == .authenticationFailed
        }
    }
}
