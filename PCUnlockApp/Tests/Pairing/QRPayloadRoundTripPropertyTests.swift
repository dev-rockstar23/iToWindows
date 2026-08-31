// Feature: pc-unlock, Property 15
// QRPayloadRoundTripPropertyTests — property-based tests verifying that the
// PairingPayload JSON encode/decode round trip is lossless.
//
// Validates: Requirements 6.1, 6.3
//
// Property 15: QR payload round trip
//   For any PairingPayload struct, decode(encode(payload)) == payload.
//
// Minimum 100 iterations via SwiftCheck's `property` operator.

import XCTest
import SwiftCheck
@testable import PCUnlockApp

// MARK: - Generators

/// Characters that are safe in both standard Base64url and JSON string contexts.
private let base64urlAlphabet: [Character] =
    Array("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_")

/// Generates a random character from the Base64url alphabet.
private let arbitraryBase64urlChar: Gen<Character> =
    Gen<Character>.fromElements(of: base64urlAlphabet)

/// Generates a random Base64url-safe string of the given length.
private func arbitraryBase64urlString(length: Int) -> Gen<String> {
    arbitraryBase64urlChar
        .proliferate(withSize: length)
        .map { String($0) }
}

/// Uppercase alphanumeric characters used for the 6-char Pairing_Code.
private let pairingCodeAlphabet: [Character] =
    Array("ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789")

/// Generates a random uppercase alphanumeric character.
private let arbitraryPairingCodeChar: Gen<Character> =
    Gen<Character>.fromElements(of: pairingCodeAlphabet)

/// Generates a 6-character uppercase alphanumeric Pairing_Code.
private let arbitraryPairingCode: Gen<String> =
    arbitraryPairingCodeChar
        .proliferate(withSize: 6)
        .map { String($0) }

// MARK: - PairingPayload: Arbitrary

/// Enables SwiftCheck to generate arbitrary `PairingPayload` instances.
///
/// Generators are constrained to realistic field shapes:
/// - `v`:    small positive integer (1–10), covering protocol version evolution.
/// - `pcId`: 22-character Base64url string (encodes 16 bytes without padding).
/// - `code`: 6 uppercase alphanumeric characters (the Pairing_Code).
/// - `svc`:  22-character Base64url string (encodes 16 UUID bytes without padding).
extension PairingPayload: Arbitrary {
    public static var arbitrary: Gen<PairingPayload> {
        // v: 1–10 (positive small protocol version numbers)
        let vGen = Gen<Int>.choose((1, 10))

        // pcId: 22 base64url chars = 16 bytes without '=' padding
        let pcIdGen = arbitraryBase64urlString(length: 22)

        // code: 6 uppercase alphanumeric chars
        let codeGen = arbitraryPairingCode

        // svc: 22 base64url chars (same shape as pcId; UUID is 16 bytes)
        let svcGen = arbitraryBase64urlString(length: 22)

        return vGen.flatMap { v in
            pcIdGen.flatMap { pcId in
                codeGen.flatMap { code in
                    svcGen.map { svc in
                        PairingPayload(v: v, pcId: pcId, code: code, svc: svc)
                    }
                }
            }
        }
    }
}

// MARK: - Property tests

/// Property-based tests for Property 15 of the PCUnlock specification.
///
/// **Property 15:** For *any* `PairingPayload` value,
/// `PairingPayload.decode(from: payload.encode()) == payload`.
///
/// This verifies that the JSON encode/decode cycle is lossless for all field
/// values that can appear in a real QR code payload (Requirements 6.1, 6.3).
///
/// Tests run a minimum of 100 iterations via SwiftCheck's `property` operator.
final class QRPayloadRoundTripPropertyTests: XCTestCase {

    // MARK: - Property 15: encode then decode equals original

    /// **Validates: Requirements 6.1, 6.3**
    ///
    /// For any arbitrary `PairingPayload`, encoding to JSON and decoding back
    /// must produce a value equal to the original.
    ///
    /// Minimum 100 iterations (SwiftCheck default is 100).
    func testProperty15_encodeDecodRoundTrip_equalsOriginal() {
        let config = CheckerArguments(
            maxAllowableSuccessfulTests: 100,
            maxAllowableDiscardedTests: 500,
            maxTestCaseSize: 100
        )

        property(
            "Property 15: decode(encode(payload)) == payload for any PairingPayload",
            arguments: config
        ) <- forAll(PairingPayload.arbitrary) { payload in

            // Encode to JSON Data.
            let encoded: Data
            do {
                encoded = try payload.encode()
            } catch {
                // Encoding must not throw for well-formed string fields.
                return false
            }

            // Decode back from JSON Data.
            let decoded: PairingPayload
            do {
                decoded = try PairingPayload.decode(from: encoded)
            } catch {
                // Decoding must succeed for data produced by encode().
                return false
            }

            // Round-trip equality: all four fields must be identical.
            return decoded == payload
        }
    }

    // MARK: - Property 15b: encoded output is valid UTF-8 JSON

    /// A supporting property: `encode()` must always produce non-empty,
    /// valid UTF-8 data. This underpins the round-trip guarantee by confirming
    /// the intermediate representation is well-formed.
    ///
    /// **Validates: Requirements 6.1, 6.3**
    ///
    /// Minimum 100 iterations.
    func testProperty15_encodedData_isNonEmptyValidUTF8() {
        let config = CheckerArguments(
            maxAllowableSuccessfulTests: 100,
            maxAllowableDiscardedTests: 500,
            maxTestCaseSize: 100
        )

        property(
            "Property 15b: encode() produces non-empty valid UTF-8 JSON",
            arguments: config
        ) <- forAll(PairingPayload.arbitrary) { payload in

            let encoded: Data
            do {
                encoded = try payload.encode()
            } catch {
                return false
            }

            // Must be non-empty.
            guard !encoded.isEmpty else { return false }

            // Must be valid UTF-8.
            guard let jsonString = String(data: encoded, encoding: .utf8) else {
                return false
            }

            // Must look like a JSON object (starts with '{' after whitespace trim).
            return jsonString.trimmingCharacters(in: .whitespaces).hasPrefix("{")
        }
    }

    // MARK: - Property 15c: field identity under round trip (per-field)

    /// Verifies each individual field survives the round trip independently,
    /// making failure messages easier to diagnose during shrinking.
    ///
    /// **Validates: Requirements 6.1, 6.3**
    ///
    /// Minimum 100 iterations.
    func testProperty15_roundTrip_preservesEachFieldIndividually() {
        let config = CheckerArguments(
            maxAllowableSuccessfulTests: 100,
            maxAllowableDiscardedTests: 500,
            maxTestCaseSize: 100
        )

        property(
            "Property 15c: each field of PairingPayload is preserved by encode/decode",
            arguments: config
        ) <- forAll(PairingPayload.arbitrary) { payload in

            guard let encoded = try? payload.encode(),
                  let decoded = try? PairingPayload.decode(from: encoded) else {
                return false
            }

            // Check each field explicitly so SwiftCheck shrinking can pinpoint
            // which field breaks first.
            guard decoded.v    == payload.v    else { return false }
            guard decoded.pcId == payload.pcId else { return false }
            guard decoded.code == payload.code else { return false }
            guard decoded.svc  == payload.svc  else { return false }

            return true
        }
    }
}
