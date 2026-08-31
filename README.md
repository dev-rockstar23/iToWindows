<div align="center">
  <img src="https://i.postimg.cc/SKV49j0S/ito-Windows.png" width="120" alt="iToWindows Unlock logo"/>
  <h1>iToWindows Unlock</h1>
  <p><strong>Unlock your Windows 11 PC with Face ID on your iPhone — no password, no PIN, no internet.</strong></p>

  [![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
  [![Platform: Windows 11](https://img.shields.io/badge/Platform-Windows%2011-0078D4?logo=windows)](https://github.com/dev-rockstar23/iToWindows/releases)
  [![Platform: iOS 16+](https://img.shields.io/badge/Platform-iOS%2016%2B-black?logo=apple)](PCUnlockApp/SETUP.md)
  [![GitHub release](https://img.shields.io/github/v/release/dev-rockstar23/iToWindows?label=Latest%20Release)](https://github.com/dev-rockstar23/iToWindows/releases/latest)

</div>

---

## ✨ How it works

1. **Pair once** — scan a QR code on your PC with the iPhone app.
2. **Walk up to your PC** — select *Unlock with iPhone* on the lock screen.
3. **Look at your iPhone** — Face ID authenticates you.
4. **PC unlocks** — all over Bluetooth, no internet required.

Your Face ID data and private key **never leave your iPhone's Secure Enclave**. The PC only ever sees a cryptographic signature.

---

## 📦 Components

| Component | Platform | Description |
|-----------|----------|-------------|
| **iToWindows Unlock** (iPhone app) | iOS 16+ | Face ID gate, BLE peripheral, QR pairing |
| **PCUnlock Service** | Windows 11 | BLE central, crypto verifier, named-pipe IPC |
| **Credential Provider** | Windows 11 | "Unlock with iPhone" tile on the lock screen |
| **Management UI** | Windows 11 | List / remove paired iPhones |
| **Installer / Uninstaller** | Windows 11 | Safe install with provider snapshot rollback |

---

## 🚀 Quick Start

### Windows PC

> **Requirements:** Windows 11, Bluetooth adapter, .NET 8 runtime

1. Go to [**Releases**](https://github.com/dev-rockstar23/iToWindows/releases/latest)
2. Download **`iToWindowsSetup.exe`**
3. Run it as Administrator and follow the wizard
4. The *Unlock with iPhone* tile will appear on your lock screen after pairing

→ Full guide: [**INSTALL.md**](INSTALL.md)

### iPhone

> **Requirements:** iPhone with Face ID, iOS 16+

The iPhone app is distributed via **TestFlight** (Apple's beta platform):

1. Install [TestFlight](https://apps.apple.com/app/testflight/id899247664) from the App Store
2. Open the invite link: *(add your TestFlight public link here after uploading)*
3. Tap **Install** inside TestFlight

→ Build & publish guide for developers: [**PCUnlockApp/SETUP.md**](PCUnlockApp/SETUP.md)

---

## 🔐 Security model

- **Asymmetric cryptography only** — ECC P-256 via Apple CryptoKit / Windows CNG
- **No custom crypto** — 100% platform APIs
- **No internet required** — everything happens over BLE on your local network
- **Replay-proof** — every unlock uses a fresh 32-byte nonce with a 60-second expiry
- **Non-destructive** — your PIN, password, and Windows Hello remain fully functional
- **Principle of least privilege** — Windows service runs as Local Service, not SYSTEM

---

## 🖥️ System requirements

### Windows
| Requirement | Minimum |
|-------------|---------|
| OS | Windows 11 (build 22000+) |
| Bluetooth | BLE 4.2+ adapter |
| Runtime | [.NET 8 Desktop Runtime](https://dotnet.microsoft.com/download/dotnet/8.0) |
| Privileges | Administrator (installer only) |

### iPhone
| Requirement | Minimum |
|-------------|---------|
| OS | iOS 16 |
| Hardware | Any iPhone with Face ID (iPhone X or later) |
| Bluetooth | On and allowed for the app |

---

## 📖 Documentation

| Document | Contents |
|----------|----------|
| [INSTALL.md](INSTALL.md) | Step-by-step Windows installation and first-time pairing |
| [PCUnlockApp/SETUP.md](PCUnlockApp/SETUP.md) | Building and distributing the iOS app |
| [.kiro/specs/pc-unlock/requirements.md](.kiro/specs/pc-unlock/requirements.md) | Full security requirements |

---

## 🏗️ Building from source

### Windows components (.NET 8)

```bash
# Clone the repo
git clone https://github.com/dev-rockstar23/iToWindows.git
cd iToWindows

# Build everything
dotnet build

# Run tests (requires Windows 11 + .NET 8 runtime)
dotnet test

# Build the installer
dotnet publish PCUnlockInstaller -c Release -r win-x64 --self-contained false
```

### iOS app (requires a Mac with Xcode 15+)

```bash
cd PCUnlockApp
# Follow PCUnlockApp/SETUP.md for the Xcode project setup
```

---

## 🤝 Contributing

Contributions are welcome! See [CONTRIBUTING.md](CONTRIBUTING.md) for guidelines.

---

## 📄 License

MIT — see [LICENSE](LICENSE)

---

<div align="center">
  <sub>Made with ❤️ by <a href="https://github.com/dev-rockstar23">dev-rockstar23</a></sub>
</div>
