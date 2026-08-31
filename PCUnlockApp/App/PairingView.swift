// iToWindows Unlock — PairingView + PairingViewModel
// Walks the user through scanning the QR code and confirming the pairing code.

import SwiftUI

// MARK: - ViewModel

@MainActor
final class PairingViewModel: ObservableObject {
    enum Phase { case idle, scanning, confirming(code: String), done, failed(String) }

    @Published var phase: Phase = .idle

    private var manager: PairingManager?

    func startPairing() {
        phase = .scanning

        let scanner    = QRScanner()
        let keyMgr     = KeyManager()
        let bleWriter  = MockPairingBLEWriter()   // swap for real BLE writer on device
        let mgr        = PairingManager(qrScanner: scanner,
                                        keyManager: keyMgr,
                                        bleWriter: bleWriter)
        self.manager = mgr

        Task {
            do {
                try await mgr.startPairing { [weak self] code in
                    Task { @MainActor in
                        self?.phase = .confirming(code: code)
                    }
                }
                phase = .done
            } catch {
                phase = .failed(error.localizedDescription)
            }
        }
    }

    func confirmCode() {
        Task {
            try? await manager?.confirmPairing()
        }
    }

    func cancel() {
        manager?.cancel()
        phase = .idle
    }
}

// MARK: - View

struct PairingView: View {
    @ObservedObject var viewModel: PairingViewModel
    @Environment(\.dismiss) private var dismiss

    var body: some View {
        VStack(spacing: 24) {
            switch viewModel.phase {
            case .idle:
                idleView

            case .scanning:
                scanningView

            case .confirming(let code):
                confirmingView(code: code)

            case .done:
                doneView

            case .failed(let msg):
                failedView(message: msg)
            }
        }
        .padding()
        .navigationTitle("Pair with PC")
        .navigationBarTitleDisplayMode(.inline)
        .toolbar {
            ToolbarItem(placement: .cancellationAction) {
                Button("Cancel") {
                    viewModel.cancel()
                    dismiss()
                }
            }
        }
    }

    // MARK: Phase views

    private var idleView: some View {
        VStack(spacing: 16) {
            Image(systemName: "qrcode.viewfinder")
                .font(.system(size: 64))
                .foregroundStyle(.blue)
            Text("Ready to Pair")
                .font(.title2.weight(.semibold))
            Text("On your PC, open PCUnlock and click **Pair New Device**. A QR code will appear — tap below to scan it.")
                .multilineTextAlignment(.center)
                .foregroundStyle(.secondary)
            Button("Scan QR Code") { viewModel.startPairing() }
                .buttonStyle(.borderedProminent)
                .controlSize(.large)
        }
    }

    private var scanningView: some View {
        VStack(spacing: 16) {
            ProgressView()
                .scaleEffect(1.5)
            Text("Point your camera at the QR code on your PC screen.")
                .multilineTextAlignment(.center)
                .foregroundStyle(.secondary)
        }
    }

    private func confirmingView(code: String) -> some View {
        VStack(spacing: 20) {
            Image(systemName: "checkmark.shield.fill")
                .font(.system(size: 56))
                .foregroundStyle(.green)
            Text("Confirm Pairing Code")
                .font(.title2.weight(.semibold))
            Text("Make sure the code below matches what's shown on your PC, then tap **Confirm** on both devices.")
                .multilineTextAlignment(.center)
                .foregroundStyle(.secondary)

            Text(code)
                .font(.system(size: 42, weight: .bold, design: .monospaced))
                .padding(.vertical, 12)
                .padding(.horizontal, 24)
                .background(.regularMaterial, in: RoundedRectangle(cornerRadius: 12))

            Button("Confirm — Codes Match") { viewModel.confirmCode() }
                .buttonStyle(.borderedProminent)
                .controlSize(.large)

            Button("Cancel", role: .cancel) { viewModel.cancel() }
                .foregroundStyle(.red)
        }
    }

    private var doneView: some View {
        VStack(spacing: 16) {
            Image(systemName: "lock.open.fill")
                .font(.system(size: 56))
                .foregroundStyle(.green)
            Text("Pairing Complete!")
                .font(.title2.weight(.semibold))
            Text("This iPhone can now unlock your PC using Face ID.")
                .multilineTextAlignment(.center)
                .foregroundStyle(.secondary)
            Button("Done") { dismiss() }
                .buttonStyle(.borderedProminent)
                .controlSize(.large)
        }
    }

    private func failedView(message: String) -> some View {
        VStack(spacing: 16) {
            Image(systemName: "xmark.circle.fill")
                .font(.system(size: 56))
                .foregroundStyle(.red)
            Text("Pairing Failed")
                .font(.title2.weight(.semibold))
            Text(message)
                .multilineTextAlignment(.center)
                .foregroundStyle(.secondary)
            Button("Try Again") { viewModel.startPairing() }
                .buttonStyle(.borderedProminent)
        }
    }
}

// MARK: - Mock BLE writer (replaced by real CBCentralManager implementation on device)

private final class MockPairingBLEWriter: PairingBLEWriting {
    func write(_ request: PairingRequest, serviceUUID: String, pcId: String) async throws {
        // Simulate BLE write latency.
        try await Task.sleep(nanoseconds: 500_000_000)
    }
}
