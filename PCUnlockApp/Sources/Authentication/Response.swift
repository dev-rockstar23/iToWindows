// Feature: pc-unlock
// Response — the signed response produced by ChallengeSigner and transmitted
// to PCUnlock_Service over BLE.
// Requirements: 2.1, 2.2, 3.1, 3.6

import Foundation

// MARK: - Response

/// The signed response returned by `ChallengeSigner` and transmitted to the
/// PC over BLE after a successful Face ID authentication.
///
/// Wire layout (BLE transport — prefixed with 4-byte LE length by BLEPeripheral):
/// ```
/// [version:1][sessionId:16][deviceId:16][signatureDER:variable]
/// ```
///
/// - `version`:      Protocol version matching the `Challenge`.
/// - `sessionId`:    UUID copied verbatim from the `Challenge` so the service
///                   can correlate the response to an active session.
/// - `deviceId`:     UUID identifying which paired device signed this challenge;
///                   the service uses it to look up the matching public key.
/// - `signatureDER`: DER-encoded ECDSA-P256-SHA256 signature over
///                   `SHA256(challenge.canonicalBytes())`.  Typically 70-72 bytes.
public struct Response: Equatable {
    /// Protocol version — matches `Challenge.version`.
    public let version: UInt8

    /// Session identifier — copied from the `Challenge` that was signed.
    public let sessionId: UUID

    /// Stable device identifier assigned at pairing time; used by the service
    /// to look up the correct public key from the Device Registry.
    public let deviceId: UUID

    /// DER-encoded ECDSA-P256 signature over `SHA256(challenge.canonicalBytes())`.
    /// Typically 70–72 bytes.
    public let signatureDER: Data

    // MARK: Init

    /// Creates a `Response`.
    ///
    /// - Parameters:
    ///   - version:      Protocol version (should match the signed `Challenge`).
    ///   - sessionId:    The `sessionId` from the signed `Challenge`.
    ///   - deviceId:     The UUID identifying the paired device that signed.
    ///   - signatureDER: The DER-encoded ECDSA-P256 signature bytes.
    public init(
        version: UInt8,
        sessionId: UUID,
        deviceId: UUID,
        signatureDER: Data
    ) {
        self.version = version
        self.sessionId = sessionId
        self.deviceId = deviceId
        self.signatureDER = signatureDER
    }
}
