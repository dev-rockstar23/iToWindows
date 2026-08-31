// Feature: pc-unlock
// PairingManager — state machine that drives the iPhone side of the QR-code
// pairing flow from payload scan to public-key transmission over BLE.
// Requirements: 6.3, 6.4, 6.5, 6.6

import Foundation
import CryptoKit
import CoreBluetooth

// MARK: - Pairing state

/// The set of states the pairing state machine can occupy.
public enum PairingState: Equatable {
    /// Waiting for the user to scan the QR code.
    case pendingQR
    /// QR scanned; Pairing_Code displayed; waiting for the user to confirm.
    case pendingConfirmation(pairingCode: String, pcId: String)
    /// Pairing completed successfully; device record written on the PC side.
    case complete(pairingId: UUID)
    /// Pairing was cancelled or timed out; all intermediate state has been discarded.
    case cancelled
}

// MARK: - Errors

/// Errors thrown by `PairingManager`.
public enum PairingManagerError: Error, Equatable {
    /// The pairing session expired before both sides confirmed (Requirement 6.6).
    case sessionExpired
    /// Key generation failed.
    case keyGenerationFailed
    /// The BLE write of the PairingRequest characteristic failed.
    case bleWriteFailed
    /// The PairingPayload had an unsupported protocol version.
    case unsupportedVersion(Int)
    /// The QR scan failed.
    case scanFailed
}

// MARK: - PairingRequest wire format

/// The JSON payload sent from the iPhone to the PC over BLE pairing
/// characteristic (`...7893`) to complete the pairing handshake.
///
/// Wire format:
/// ```json
/// { "pairingCode": "A3X7KQ", "publicKeyDER": "<base64-SPKI>", "deviceId": "<uuid>" }
/// ```
public struct PairingRequest: Codable {
    /// Echo of the Pairing_Code from the QR payload — used by the PC to verify
    /// out-of-band confirmation (Requirement 6.5).
    public let pairingCode: String
    /// Base64-encoded SPKI DER bytes of the iPhone's P-256 public key.
    public let publicKeyDER: String
    /// Stable device identifier (UUID) used to correlate the DeviceRecord.
    public let deviceId: String
}

// MARK: - Protocol

/// Defines the contract for the iPhone-side pairing state machine.
public protocol PairingManaging {
    /// The current pairing state.
    var state: PairingState { get }

    /// Runs the full pairing flow end-to-end:
    /// 1. Scans the QR code from the camera.
    /// 2. Transitions to `pendingConfirmation` and surfaces the Pairing_Code.
    /// 3. Awaits the caller's `confirmPairing()` call within the 120-second window.
    /// 4. Generates a key pair and sends the `PairingRequest` over BLE.
    /// 5. Transitions to `complete` on success, or `cancelled` on timeout/error.
    ///
    /// - Parameter onCodeReady: Called once the Pairing_Code is decoded from
    ///   the QR payload, passing the code string so the UI can display it.
    ///   The caller must invoke `confirmPairing()` after the user visually
    ///   verifies the code on both devices.
    func startPairing(onCodeReady: @escaping (String) -> Void) async throws
    /// Called by the UI once the user has visually confirmed the Pairing_Code.
    func confirmPairing() async throws
    /// Cancels an in-progress pairing and discards all intermediate state.
    func cancel()
}

// MARK: - PairingManager

/// Concrete implementation of `PairingManaging`.
///
/// The pairing window is enforced with a 120-second deadline from the moment
/// the QR code is scanned (Requirement 6.6).  If `confirmPairing` is not
/// called within that window the session transitions to `.cancelled` and all
/// intermediate state (key material, BLE connection, payload) is discarded.
public final class PairingManager: PairingManaging {

    // MARK: - Dependencies

    private let qrScanner: QRScanning
    private let keyManager: KeyManaging
    private let bleWriter: PairingBLEWriting
    /// Pairing session duration (Requirement 6.6: 120 seconds).
    private let sessionTimeout: TimeInterval

    // MARK: - State

    public private(set) var state: PairingState = .pendingQR

    /// The payload decoded from the QR code — held only during the
    /// `pendingConfirmation` state; cleared on completion or cancellation.
    private var pendingPayload: PairingPayload?
    /// The generated public key held until transmission — cleared after send.
    private var pendingPublicKey: P256.Signing.PublicKey?
    /// The pairing-scoped UUID assigned to this session.
    private var pairingId: UUID?
    /// Continuation that `startPairing` awaits on, resolved by `confirmPairing`.
    private var confirmationContinuation: CheckedContinuation<Void, Error>?
    /// Flag that signals whether the user has confirmed.
    private var confirmed = false
    /// Task handle for the 120-second timeout watchdog.
    private var timeoutTask: Task<Void, Never>?

    // MARK: - Init

    /// Creates a `PairingManager`.
    ///
    /// - Parameters:
    ///   - qrScanner: Provides the QR scan step.
    ///   - keyManager: Generates and stores the Secure Enclave key pair.
    ///   - bleWriter: Writes the `PairingRequest` to the BLE pairing
    ///     characteristic.
    ///   - sessionTimeout: How long to wait for user confirmation before
    ///     cancelling (default 120 s, Requirement 6.6).
    public init(
        qrScanner: QRScanning,
        keyManager: KeyManaging,
        bleWriter: PairingBLEWriting,
        sessionTimeout: TimeInterval = 120
    ) {
        self.qrScanner = qrScanner
        self.keyManager = keyManager
        self.bleWriter = bleWriter
        self.sessionTimeout = sessionTimeout
    }

    // MARK: - PairingManaging

    public func startPairing(onCodeReady: @escaping (String) -> Void) async throws {
        // Reset to a clean state before starting.
        discardIntermediateState()
        state = .pendingQR

        // Step 1: Scan the QR code and decode the PairingPayload.
        let payload: PairingPayload
        do {
            payload = try await qrScanner.scan()
        } catch {
            state = .cancelled
            discardIntermediateState()
            throw PairingManagerError.scanFailed
        }

        // Verify supported protocol version.
        guard payload.v == 1 else {
            state = .cancelled
            discardIntermediateState()
            throw PairingManagerError.unsupportedVersion(payload.v)
        }

        // Step 2: Surface the Pairing_Code to the user (Requirement 6.4).
        pendingPayload = payload
        state = .pendingConfirmation(pairingCode: payload.code, pcId: payload.pcId)
        onCodeReady(payload.code)

        // Step 3: Await user confirmation within the 120-second window.
        // Set up the timeout watchdog.
        let timeoutDuration = sessionTimeout
        timeoutTask = Task { [weak self] in
            try? await Task.sleep(nanoseconds: UInt64(timeoutDuration * 1_000_000_000))
            self?.fireTimeout()
        }

        do {
            try await withCheckedThrowingContinuation { (cont: CheckedContinuation<Void, Error>) in
                self.confirmationContinuation = cont
            }
        } catch {
            // Timeout or external cancel.
            discardIntermediateState()
            state = .cancelled
            throw error
        }

        timeoutTask?.cancel()
        timeoutTask = nil

        // Step 4: Generate key pair (Requirement 6.5: transmit public key).
        let id = UUID()
        pairingId = id
        let publicKey: P256.Signing.PublicKey
        do {
            publicKey = try keyManager.generateKeyPair(forPairing: id)
        } catch {
            discardIntermediateState()
            state = .cancelled
            throw PairingManagerError.keyGenerationFailed
        }
        pendingPublicKey = publicKey

        // Encode the public key as SPKI DER (X9.63 uncompressed → base64).
        let spkiData = publicKey.x963Representation
        let publicKeyDERBase64 = spkiData.base64EncodedString()

        // Build and transmit the PairingRequest.
        let request = PairingRequest(
            pairingCode: payload.code,
            publicKeyDER: publicKeyDERBase64,
            deviceId: id.uuidString
        )

        do {
            try await bleWriter.write(request, serviceUUID: payload.svc, pcId: payload.pcId)
        } catch {
            discardIntermediateState()
            state = .cancelled
            throw PairingManagerError.bleWriteFailed
        }

        // Step 5: Mark complete.
        state = .complete(pairingId: id)
        // Clear in-flight material now that pairing is done.
        pendingPayload = nil
        pendingPublicKey = nil
    }

    public func confirmPairing() async throws {
        guard case .pendingConfirmation = state else { return }
        confirmed = true
        confirmationContinuation?.resume()
        confirmationContinuation = nil
    }

    public func cancel() {
        fireTimeout()
    }

    // MARK: - Private

    private func fireTimeout() {
        timeoutTask?.cancel()
        timeoutTask = nil
        if let cont = confirmationContinuation {
            confirmationContinuation = nil
            cont.resume(throwing: PairingManagerError.sessionExpired)
        }
        discardIntermediateState()
        if case .complete = state { /* don't overwrite */ } else {
            state = .cancelled
        }
    }

    /// Clears all sensitive intermediate state from memory (Requirement 6.6).
    private func discardIntermediateState() {
        pendingPayload = nil
        pendingPublicKey = nil
        pairingId = nil
        confirmed = false
        confirmationContinuation = nil
    }
}

// MARK: - BLE writing abstraction

/// Abstracts the BLE write of a `PairingRequest` to the PC's pairing
/// characteristic (`...7893`).  A concrete implementation wraps
/// `CBCentralManager`; a mock is used in unit tests.
public protocol PairingBLEWriting {
    /// Connects to the PC's BLE GATT server identified by `serviceUUID` and
    /// `pcId`, and writes the `PairingRequest` to the pairing characteristic.
    ///
    /// - Parameters:
    ///   - request: The pairing request to transmit.
    ///   - serviceUUID: Base64Url-encoded bytes of the BLE service UUID from
    ///     the `PairingPayload.svc` field.
    ///   - pcId: Base64Url-encoded PC identity token — used to identify the
    ///     correct peripheral when multiple PCUnlock devices are nearby.
    /// - Throws: Any error that occurs during the BLE write.
    func write(_ request: PairingRequest, serviceUUID: String, pcId: String) async throws
}
