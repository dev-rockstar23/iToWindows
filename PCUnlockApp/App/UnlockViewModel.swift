// iToWindows Unlock — UnlockViewModel
// Drives the one-tap unlock flow: Face ID → BLE → done.

import Foundation
import CryptoKit
@preconcurrency import Combine

@MainActor
final class UnlockViewModel: ObservableObject {
    @Published var isUnlocking   = false
    @Published var statusMessage: String? = nil
    @Published var isError       = false

    private let keyManager   = KeyManager()

    func startUnlock() {
        guard !isUnlocking else { return }
        isUnlocking   = true
        statusMessage = "Connecting to PC…"
        isError       = false

        Task {
            defer { isUnlocking = false }
            do {
                // The BLE peripheral advertising and challenge/response flow
                // is handled by BLEPeripheral (Phase 2).  This stub shows the
                // UI state machine; wire to real BLEPeripheral when running on device.
                try await simulateUnlockFlow()
                statusMessage = "PC unlocked ✓"
                isError       = false
            } catch {
                statusMessage = "Unlock failed: \(error.localizedDescription)"
                isError       = true
            }
        }
    }

    // Placeholder — replace with real BLEPeripheral.startUnlockSession().
    private func simulateUnlockFlow() async throws {
        try await Task.sleep(nanoseconds: 1_500_000_000)
    }
}
