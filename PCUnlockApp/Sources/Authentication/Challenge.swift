// Feature: pc-unlock
// Challenge — the structured authentication challenge issued by PCUnlock_Service.
// Requirements: 2.1, 2.2, 5.1, 5.2

import Foundation

// MARK: - Decoding errors

/// Errors thrown when decoding a `Challenge` from its canonical wire bytes.
public enum ChallengeDecodingError: Error, Equatable {
    /// The supplied buffer is not exactly 57 bytes.
    case invalidLength(Int)
    /// The `expiresAt` timestamp is in the past; the challenge has expired.
    case challengeExpired
}

// MARK: - Challenge

/// A structured authentication challenge issued by `PCUnlock_Service` and
/// received by the iPhone over BLE.
///
/// Canonical encoding (for signing, 57 bytes, little-endian):
/// ```
/// [version:1][sessionId:16][nonce:32][expiresAt:8]
/// ```
/// The ECDSA signature is computed over `SHA-256(canonicalBytes)`.
public struct Challenge: Equatable {
    /// Protocol version — currently `1`.
    public let version: UInt8

    /// Session identifier — unique per unlock attempt.
    public let sessionId: UUID

    /// Cryptographically random single-use value; exactly 32 bytes.
    public let nonce: Data

    /// Unix epoch seconds (UTC) at which the challenge expires.
    public let expiresAt: Int64

    // MARK: Init

    /// Creates a `Challenge`.
    ///
    /// - Parameters:
    ///   - version: Protocol version (default `1`).
    ///   - sessionId: A UUID unique to this unlock session.
    ///   - nonce: Exactly 32 bytes of CSPRNG data.
    ///   - expiresAt: Unix epoch seconds for the expiry time.
    public init(
        version: UInt8 = 1,
        sessionId: UUID,
        nonce: Data,
        expiresAt: Int64
    ) {
        self.version = version
        self.sessionId = sessionId
        self.nonce = nonce
        self.expiresAt = expiresAt
    }

    // MARK: Canonical encoding

    /// Returns the 57-byte canonical little-endian binary representation used
    /// as input to the SHA-256 digest before signing.
    ///
    /// Layout: `[version:1][sessionId:16][nonce:32][expiresAt:8]`
    public func canonicalBytes() -> Data {
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
}

// MARK: - Wire-format decoding

extension Challenge {
    /// Canonical wire format size in bytes.
    public static let wireByteCount = 57

    /// Decodes a `Challenge` from its 57-byte canonical little-endian binary
    /// wire representation and validates that the challenge has not expired.
    ///
    /// Expected layout:
    /// ```
    /// [version:1][sessionId:16][nonce:32][expiresAt:8 LE int64]
    /// ```
    ///
    /// - Parameter bytes: Exactly 57 bytes received over BLE.
    /// - Throws:
    ///   - `ChallengeDecodingError.invalidLength` if `bytes.count != 57`.
    ///   - `ChallengeDecodingError.challengeExpired` if `expiresAt` ≤ now.
    public init(from bytes: Data) throws {
        guard bytes.count == Challenge.wireByteCount else {
            throw ChallengeDecodingError.invalidLength(bytes.count)
        }

        var offset = bytes.startIndex

        // version — 1 byte
        let version = bytes[offset]
        offset += 1

        // sessionId — 16 bytes (UUID big-endian wire format)
        let uuidBytes = bytes[offset ..< offset + 16]
        let sessionId = UUID(uuid: (
            uuidBytes[uuidBytes.startIndex],
            uuidBytes[uuidBytes.startIndex + 1],
            uuidBytes[uuidBytes.startIndex + 2],
            uuidBytes[uuidBytes.startIndex + 3],
            uuidBytes[uuidBytes.startIndex + 4],
            uuidBytes[uuidBytes.startIndex + 5],
            uuidBytes[uuidBytes.startIndex + 6],
            uuidBytes[uuidBytes.startIndex + 7],
            uuidBytes[uuidBytes.startIndex + 8],
            uuidBytes[uuidBytes.startIndex + 9],
            uuidBytes[uuidBytes.startIndex + 10],
            uuidBytes[uuidBytes.startIndex + 11],
            uuidBytes[uuidBytes.startIndex + 12],
            uuidBytes[uuidBytes.startIndex + 13],
            uuidBytes[uuidBytes.startIndex + 14],
            uuidBytes[uuidBytes.startIndex + 15]
        ))
        offset += 16

        // nonce — 32 bytes
        let nonce = Data(bytes[offset ..< offset + 32])
        offset += 32

        // expiresAt — 8 bytes, little-endian int64
        let expiresAtBytes = bytes[offset ..< offset + 8]
        var expiresAtLE: Int64 = 0
        withUnsafeMutableBytes(of: &expiresAtLE) { dest in
            dest.copyBytes(from: expiresAtBytes)
        }
        let expiresAt = Int64(littleEndian: expiresAtLE)

        // Validate that the challenge has not already expired.
        let now = Int64(Date().timeIntervalSince1970)
        guard expiresAt > now else {
            throw ChallengeDecodingError.challengeExpired
        }

        self.init(
            version: version,
            sessionId: sessionId,
            nonce: nonce,
            expiresAt: expiresAt
        )
    }
}
