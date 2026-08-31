// Feature: pc-unlock
// PairingPayload — QR code payload transmitted from PC to iPhone during pairing.
// Requirements: 6.1, 6.3

import Foundation

// MARK: - PairingPayload

/// The JSON payload extracted from the pairing QR code.
///
/// Wire format (JSON):
/// ```json
/// { "v": 1, "pcId": "<base64url-pcIdentityToken>", "code": "A3X7KQ", "svc": "<base64url-BLE-service-UUID>" }
/// ```
///
/// Fields:
/// - `v`    — protocol version (currently 1).
/// - `pcId` — Base64Url-encoded 16-byte PC identity token.
/// - `code` — 6-character alphanumeric uppercase Pairing_Code.
/// - `svc`  — Base64Url-encoded bytes of the BLE Pairing service UUID.
public struct PairingPayload: Codable, Equatable {
    /// Protocol version. Currently 1.
    public let v: Int

    /// Base64Url-encoded 16-byte PC identity token.
    public let pcId: String

    /// 6-character alphanumeric uppercase Pairing_Code.
    public let code: String

    /// Base64Url-encoded bytes of the BLE Pairing service UUID.
    public let svc: String

    /// Creates a `PairingPayload` with the given field values.
    public init(v: Int, pcId: String, code: String, svc: String) {
        self.v    = v
        self.pcId = pcId
        self.code = code
        self.svc  = svc
    }
}

// MARK: - Encode / Decode

extension PairingPayload {

    // MARK: Errors

    /// Errors thrown by `PairingPayload.decode(from:)`.
    public enum DecodingError: Error, Equatable {
        /// The supplied `Data` is not valid UTF-8 JSON.
        case invalidJSON
    }

    // MARK: Encode

    /// Encodes the receiver to a compact UTF-8 JSON `Data` value.
    ///
    /// - Returns: JSON-encoded data, e.g.
    ///   `{"v":1,"pcId":"...","code":"A3X7KQ","svc":"..."}`.
    /// - Throws: `EncodingError` if JSON serialisation fails (should not happen
    ///   for well-formed string fields).
    public func encode() throws -> Data {
        let encoder = JSONEncoder()
        // Produce compact output without any key sorting so the round-trip is
        // stable and field order matches the Windows-side wire format.
        encoder.outputFormatting = []
        return try encoder.encode(self)
    }

    // MARK: Decode

    /// Decodes a `PairingPayload` from UTF-8 JSON `Data`.
    ///
    /// - Parameter data: JSON data as produced by `encode()` or the Windows
    ///   `PairingHandler`.
    /// - Returns: A fully initialised `PairingPayload`.
    /// - Throws: `DecodingError.invalidJSON` if the data cannot be parsed, or a
    ///   Swift `DecodingError` if a required field is missing or has the wrong type.
    public static func decode(from data: Data) throws -> PairingPayload {
        let decoder = JSONDecoder()
        return try decoder.decode(PairingPayload.self, from: data)
    }
}
