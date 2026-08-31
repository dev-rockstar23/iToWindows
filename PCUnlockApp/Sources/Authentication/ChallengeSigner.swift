// Feature: pc-unlock
// ChallengeSigner — signs a Challenge using the Secure Enclave P-256 private
// key, gated on a successful Face ID authentication.
// Requirements: 2.1, 2.2, 2.3, 2.4, 3.1, 3.6

import Foundation
import CryptoKit

// MARK: - Errors

/// Errors thrown by `ChallengeSigning` implementations.
public enum ChallengeSignerError: Error, Equatable {
    /// Face ID authentication was not performed or failed; the challenge has
    /// been discarded and no Response was produced.
    case authenticationFailed

    /// The challenge's `expiresAt` timestamp is in the past.
    case challengeExpired

    /// The signing operation itself failed (Secure Enclave error).
    case signingFailed
}

// MARK: - Protocol

/// Defines the contract for producing a signed `Response` from a `Challenge`.
///
/// Implementations MUST call `FaceIDManaging.authenticate` before performing
/// any signing operation (Requirements 2.1, 2.2).
public protocol ChallengeSigning {
    /// Signs a challenge after gating on Face ID authentication and returns a
    /// fully populated `Response` struct.
    ///
    /// - Parameters:
    ///   - challenge: The challenge to sign.
    ///   - deviceId:  The stable UUID identifying this paired device; included
    ///                in the `Response` so the service can look up the public key.
    ///   - key:       The Secure Enclave P-256 signing key.
    /// - Returns: A `Response` containing the DER-encoded ECDSA-P256-SHA256
    ///            signature over `SHA256(challenge.canonicalBytes())`, along
    ///            with the `sessionId` copied from `challenge` and the provided
    ///            `deviceId`.
    /// - Throws:
    ///   - `ChallengeSignerError.authenticationFailed` if Face ID fails.
    ///   - `ChallengeSignerError.challengeExpired` if `expiresAt` is in the past.
    ///   - `ChallengeSignerError.signingFailed` on a Secure Enclave error.
    func sign(
        challenge: Challenge,
        deviceId: UUID,
        usingKey key: SecureEnclave.P256.Signing.PrivateKey
    ) async throws -> Response
}

// MARK: - Concrete implementation

/// Concrete signer that:
/// 1. Validates the challenge expiry.
/// 2. Calls `FaceIDManaging.authenticate` — discards and throws on failure.
/// 3. Computes `digest = SHA256(canonicalBytes(challenge))`.
/// 4. Signs with the Secure Enclave key.
/// 5. Constructs and returns a `Response` struct with the DER signature,
///    the `sessionId` from the challenge, and the caller-supplied `deviceId`.
public final class ChallengeSigner: ChallengeSigning {

    private let faceIDManager: FaceIDManaging
    private let authReason: String

    /// Creates a `ChallengeSigner`.
    ///
    /// - Parameters:
    ///   - faceIDManager: The biometric gate.  Inject a mock during testing.
    ///   - authReason: The localised reason string shown to the user by Face ID.
    public init(
        faceIDManager: FaceIDManaging,
        authReason: String = "Authenticate to unlock your PC"
    ) {
        self.faceIDManager = faceIDManager
        self.authReason = authReason
    }

    public func sign(
        challenge: Challenge,
        deviceId: UUID,
        usingKey key: SecureEnclave.P256.Signing.PrivateKey
    ) async throws -> Response {
        // 1. Reject expired challenges before touching Face ID.
        let now = Int64(Date().timeIntervalSince1970)
        guard challenge.expiresAt > now else {
            throw ChallengeSignerError.challengeExpired
        }

        // 2. Face ID gate — MUST succeed before any signing occurs.
        //    Requirements 2.1, 2.2: discard the challenge on any failure result.
        let authResult = await faceIDManager.authenticate(reason: authReason)
        switch authResult {
        case .failure:
            // Discard the challenge; produce no Response.
            throw ChallengeSignerError.authenticationFailed
        case .success:
            break
        }

        // 3. Compute digest = SHA256(canonicalBytes(challenge)).
        //    Requirement 3.6: SHA-256 as the digest algorithm.
        let canonical = challenge.canonicalBytes()
        let digest = SHA256.hash(data: canonical)

        // 4. Sign with Secure Enclave key — returns DER-encoded signature.
        //    Requirement 3.1, 3.6: use CryptoKit SE P-256 API exclusively.
        let derSignature: Data
        do {
            let signature = try key.signature(for: digest)
            derSignature = signature.derRepresentation
        } catch {
            throw ChallengeSignerError.signingFailed
        }

        // 5. Construct and return the Response.
        return Response(
            version: challenge.version,
            sessionId: challenge.sessionId,
            deviceId: deviceId,
            signatureDER: derSignature
        )
    }
}
