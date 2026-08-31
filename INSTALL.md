# iToWindows Unlock — Installation Guide

<div align="center">
  <img src="https://i.postimg.cc/SKV49j0S/ito-Windows.png" width="80" alt="iToWindows Unlock"/>
</div>

---

## Before you begin

Make sure you have:

- ✅ Windows 11 (build 22000 or later)
- ✅ Bluetooth adapter that supports BLE 4.2+
- ✅ [.NET 8 Desktop Runtime](https://dotnet.microsoft.com/en-us/download/dotnet/8.0) installed
- ✅ An iPhone with Face ID running iOS 16+
- ✅ At least one other sign-in method active (PIN, password, or Windows Hello) — **you cannot be locked out**

---

## Part 1 — Install on Windows

### Step 1 — Download the installer

1. Go to [**Releases**](https://github.com/dev-rockstar23/iToWindows/releases/latest)
2. Under **Assets**, download **`iToWindowsSetup.exe`**

### Step 2 — Run the installer

1. Right-click `iToWindowsSetup.exe` → **Run as Administrator**
2. If Windows SmartScreen appears, click **More info → Run anyway**
   *(the app is open source — you can audit the code before running)*
3. Follow the installer wizard:
   - Accept the license agreement
   - Choose install location (default: `C:\Program Files\iToWindows Unlock\`)
   - Click **Install**

The installer will:
- ✔ Snapshot your current credential providers (safety backup)
- ✔ Register the PCUnlock Windows Service
- ✔ Register the "Unlock with iPhone" lock-screen tile
- ✔ Verify all your existing sign-in methods still work
- ✔ Roll back automatically if anything goes wrong

### Step 3 — Verify the service is running

Open **Task Manager → Services** tab and confirm `PCUnlockService` shows **Running**.

Or check from PowerShell:
```powershell
Get-Service PCUnlockService
```

---

## Part 2 — Install the iPhone app

### Option A — TestFlight (recommended)

1. On your iPhone, install [**TestFlight**](https://apps.apple.com/app/testflight/id899247664) from the App Store (it's free)
2. Open the TestFlight invite link:
   > *(The developer will add the public TestFlight link here)*
3. Tap **Install** — the **iToWindows Unlock** app will appear on your home screen

### Option B — Build from source (developers)

See [PCUnlockApp/SETUP.md](PCUnlockApp/SETUP.md) for full Xcode build and distribution instructions.

---

## Part 3 — Pair your iPhone with your PC

This only needs to be done **once per PC**.

### On your PC

1. Open **iToWindows Management** from the Start menu  
   *(or search for "iToWindows" in the Start menu)*
2. Click **Pair New Device**
3. A QR code will appear on screen — keep this window open

### On your iPhone

1. Open the **iToWindows Unlock** app
2. Tap **Pair with a PC**
3. Allow camera access when prompted
4. Point your camera at the QR code on your PC screen

### Confirm the pairing code

Both your PC and iPhone will display a **6-character code** (e.g. `A3X7KQ`).

- ✅ If the codes **match** — tap **Confirm** on your iPhone and click **Confirm** on your PC
- ❌ If the codes **don't match** — tap **Cancel** on both devices and try again (possible rogue device nearby)

Pairing completes in a few seconds. You'll see a confirmation on both screens.

---

## Part 4 — Unlock your PC

1. Let your PC go to the lock screen
2. Click **Unlock with iPhone** tile
3. Pick up your iPhone and look at it — Face ID authenticates you
4. The PC unlocks automatically

> **Tip:** Your iPhone screen needs to be on (or it will wake automatically when BLE connects). Keep the iPhone within ~10 metres of the PC.

---

## Managing paired devices

Open **iToWindows Management** from the Start menu to:

| Action | How |
|--------|-----|
| See all paired iPhones | List appears automatically |
| Remove a device | Select it → click **Remove Device** |
| Remove a **lost** iPhone | Select it → click **Remove Lost Device…** → enter your Windows PIN/password |

---

## Uninstalling

### Option A — Settings
**Settings → Apps → iToWindows Unlock → Uninstall**

### Option B — Control Panel
**Control Panel → Programs → Programs and Features → iToWindows Unlock → Uninstall**

The uninstaller will:
- ✔ Stop and remove the PCUnlock Service
- ✔ Remove the lock-screen tile
- ✔ Restore any credential providers that were active before installation
- ✔ Delete all pairing data and cryptographic material from your PC

---

## Troubleshooting

### "Unlock with iPhone" tile doesn't appear

| Cause | Fix |
|-------|-----|
| PCUnlock Service not running | Open Services, start `PCUnlockService` |
| No paired iPhones | Complete the pairing flow in iToWindows Management |
| Bluetooth is off | Turn on Bluetooth in Windows Settings |

### iPhone not found during unlock

- Make sure Bluetooth is on and the iPhone is within ~10 metres
- Make sure the iToWindows Unlock app is installed and not force-closed
- Try the unlock again — the BLE scan has a 15-second window

### Pairing QR code expires

The pairing window is 120 seconds. If it expires, click **Pair New Device** again to generate a fresh QR code.

### Installer rolls back / fails

The installer will not proceed if it cannot confirm all your existing credential providers are intact. This is a safety feature. Check:
- You are running as Administrator
- Windows Update is not currently installing a major update
- No third-party security software is blocking registry writes

---

## Security notes

- Your **Face ID biometrics never leave your iPhone**
- Your **Windows password/PIN is never used or stored** by iToWindows
- All BLE communication uses authenticated pairing with encrypted characteristics
- Every unlock uses a fresh cryptographic nonce — replayed BLE traffic cannot unlock your PC
- The Windows Service runs as **Local Service** (not SYSTEM) with minimum required privileges

---

## Getting help

- 🐛 **Bug reports:** [GitHub Issues](https://github.com/dev-rockstar23/iToWindows/issues)
- 💬 **Questions:** [GitHub Discussions](https://github.com/dev-rockstar23/iToWindows/discussions)
