// Feature: pc-unlock
// QRScanner — wraps AVFoundation / VisionKit to scan QR codes from the camera
// and decode them as PairingPayload values.
// Requirements: 6.3

import Foundation
import AVFoundation

// MARK: - Protocol

/// Defines the contract for scanning and decoding a pairing QR code.
public protocol QRScanning {
    /// Scans a QR code from the live camera feed and returns the decoded payload.
    ///
    /// - Returns: The `PairingPayload` decoded from the QR code.
    /// - Throws: `QRScannerError` if scanning fails or the payload is invalid.
    func scan() async throws -> PairingPayload
}

// MARK: - Errors

/// Errors thrown by `QRScanner`.
public enum QRScannerError: Error, Equatable {
    /// Camera access was denied or restricted.
    case cameraAccessDenied
    /// No QR code was found within the allotted scan window.
    case scanTimeout
    /// A QR code was found but its content could not be decoded as a `PairingPayload`.
    case invalidPayload
    /// The scanned payload has an unsupported protocol version.
    case unsupportedVersion(Int)
}

// MARK: - ScanResult (internal)

/// Internal result delivered from the capture delegate to the async continuation.
private enum ScanResult {
    case success(String)
    case failure(QRScannerError)
}

// MARK: - QRScanner

/// Concrete QR scanner backed by `AVFoundation`.
///
/// Usage:
/// ```swift
/// let scanner = QRScanner()
/// let payload = try await scanner.scan()
/// ```
///
/// The scanner starts a capture session, waits for the first QR-code string
/// that looks like a PCUnlock payload, decodes it as `PairingPayload`, and
/// stops the session.  The scan times out after `scanTimeout` seconds if no
/// valid code is presented.
public final class QRScanner: NSObject, QRScanning {

    private let scanTimeout: TimeInterval
    /// Supported protocol version.
    private let supportedVersion: Int = 1

    private var captureSession: AVCaptureSession?
    private var continuation: CheckedContinuation<PairingPayload, Error>?

    /// Creates a `QRScanner`.
    ///
    /// - Parameter scanTimeout: Seconds to wait before throwing `.scanTimeout`.
    ///   Defaults to 60 seconds (pairing window is 120 s; scan is the first half).
    public init(scanTimeout: TimeInterval = 60) {
        self.scanTimeout = scanTimeout
    }

    // MARK: - QRScanning

    public func scan() async throws -> PairingPayload {
        try await withCheckedThrowingContinuation { continuation in
            self.continuation = continuation

            let status = AVCaptureDevice.authorizationStatus(for: .video)
            switch status {
            case .notDetermined:
                AVCaptureDevice.requestAccess(for: .video) { [weak self] granted in
                    if granted { self?.startSession() }
                    else { self?.finish(.failure(.cameraAccessDenied)) }
                }
            case .authorized:
                startSession()
            default:
                finish(.failure(.cameraAccessDenied))
            }

            // Schedule timeout.
            let timeoutSeconds = self.scanTimeout
            Task { [weak self] in
                try? await Task.sleep(nanoseconds: UInt64(timeoutSeconds * 1_000_000_000))
                self?.finish(.failure(.scanTimeout))
            }
        }
    }

    // MARK: - Session management

    private func startSession() {
        let session = AVCaptureSession()
        captureSession = session

        guard let device = AVCaptureDevice.default(for: .video),
              let input  = try? AVCaptureDeviceInput(device: device) else {
            finish(.failure(.cameraAccessDenied))
            return
        }

        let output = AVCaptureMetadataOutput()
        session.beginConfiguration()
        session.addInput(input)
        session.addOutput(output)
        session.commitConfiguration()

        output.setMetadataObjectsDelegate(self, queue: DispatchQueue.global(qos: .userInitiated))
        output.metadataObjectTypes = [.qr]

        session.startRunning()
    }

    private func stopSession() {
        captureSession?.stopRunning()
        captureSession = nil
    }

    // MARK: - Deliver result

    private func finish(_ result: ScanResult) {
        // Guard against duplicate delivery (timeout races with a valid scan).
        guard let cont = continuation else { return }
        continuation = nil
        stopSession()

        switch result {
        case .success(let rawString):
            guard let data = rawString.data(using: .utf8),
                  let payload = try? PairingPayload.decode(from: data) else {
                cont.resume(throwing: QRScannerError.invalidPayload)
                return
            }
            guard payload.v == supportedVersion else {
                cont.resume(throwing: QRScannerError.unsupportedVersion(payload.v))
                return
            }
            cont.resume(returning: payload)
        case .failure(let error):
            cont.resume(throwing: error)
        }
    }
}

// MARK: - AVCaptureMetadataOutputObjectsDelegate

extension QRScanner: AVCaptureMetadataOutputObjectsDelegate {
    public func metadataOutput(
        _ output: AVCaptureMetadataOutput,
        didOutput metadataObjects: [AVMetadataObject],
        from connection: AVCaptureConnection
    ) {
        guard let obj = metadataObjects.first as? AVMetadataMachineReadableCodeObject,
              obj.type == .qr,
              let rawString = obj.stringValue else {
            return
        }
        finish(.success(rawString))
    }
}
