// iToWindows Unlock — Main UI
// Provides Unlock and Pair actions.

import SwiftUI

struct ContentView: View {
    @StateObject private var unlockVM  = UnlockViewModel()
    @StateObject private var pairingVM = PairingViewModel()

    var body: some View {
        NavigationStack {
            VStack(spacing: 32) {

                // ── App logo ──────────────────────────────────────────────
                Image("AppIcon")
                    .resizable()
                    .scaledToFit()
                    .frame(width: 96, height: 96)
                    .clipShape(RoundedRectangle(cornerRadius: 22, style: .continuous))
                    .shadow(radius: 8)

                Text("iToWindows Unlock")
                    .font(.title2.weight(.semibold))

                Divider()

                // ── Unlock card ───────────────────────────────────────────
                GroupBox {
                    VStack(alignment: .leading, spacing: 12) {
                        Label("Unlock PC", systemImage: "lock.open.fill")
                            .font(.headline)
                        Text("Tap below to authenticate with Face ID and unlock your paired Windows PC over Bluetooth.")
                            .font(.subheadline)
                            .foregroundStyle(.secondary)

                        Button(action: { unlockVM.startUnlock() }) {
                            Label("Unlock with Face ID", systemImage: "faceid")
                                .frame(maxWidth: .infinity)
                        }
                        .buttonStyle(.borderedProminent)
                        .controlSize(.large)
                        .disabled(unlockVM.isUnlocking)

                        if let msg = unlockVM.statusMessage {
                            Text(msg)
                                .font(.caption)
                                .foregroundStyle(unlockVM.isError ? .red : .secondary)
                        }
                    }
                    .padding(4)
                }

                // ── Pair card ─────────────────────────────────────────────
                GroupBox {
                    VStack(alignment: .leading, spacing: 12) {
                        Label("Pair with a PC", systemImage: "qrcode.viewfinder")
                            .font(.headline)
                        Text("Scan the QR code shown on your PC to pair this iPhone for the first time.")
                            .font(.subheadline)
                            .foregroundStyle(.secondary)

                        NavigationLink {
                            PairingView(viewModel: pairingVM)
                        } label: {
                            Label("Pair New PC…", systemImage: "plus.circle")
                                .frame(maxWidth: .infinity)
                        }
                        .buttonStyle(.bordered)
                        .controlSize(.large)
                    }
                    .padding(4)
                }

                Spacer()
            }
            .padding()
            .navigationTitle("")
            .navigationBarTitleDisplayMode(.inline)
        }
    }
}

// MARK: - Preview
#Preview {
    ContentView()
}
