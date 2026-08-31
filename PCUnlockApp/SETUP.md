# iToWindows Unlock — iOS App Setup Guide

## App details
- **Name:** iToWindows Unlock  
- **Logo:** `App/Assets.xcassets/AppIcon.appiconset/itoWindows.png`  
  (download from https://i.postimg.cc/SKV49j0S/ito-Windows.png and place there)

---

## Requirements
| Tool | Version |
|------|---------|
| Mac | macOS 13 Ventura or later |
| Xcode | 15 or later |
| iPhone | iOS 16+, with Face ID |
| Apple Developer account | Free (personal device only) or $99/yr (TestFlight/App Store) |

---

## Step 1 — Get the code onto a Mac
Copy the entire `PCUnlockApp/` folder to your Mac, or clone the repo.

## Step 2 — Add the app icon
1. Download the logo: https://i.postimg.cc/SKV49j0S/ito-Windows.png  
2. Save it as:  
   `PCUnlockApp/App/Assets.xcassets/AppIcon.appiconset/itoWindows.png`  
   (1024 × 1024 px PNG, no alpha channel for App Store)

## Step 3 — Create the Xcode project
Open Terminal on your Mac:
```bash
cd /path/to/PCUnlockApp

# Open Xcode and create a new iOS App project:
#   Product Name:        iToWindows Unlock
#   Bundle Identifier:   com.yourname.itowindows-unlock
#   Interface:           SwiftUI
#   Language:            Swift
#   Minimum iOS:         16.0
```

Then in Xcode:
1. **File → Add Package Dependencies** → add the local `PCUnlockApp` package  
   (or drag `Package.swift` into the project)
2. Copy the files from `App/` into the Xcode project's app target
3. In the target's **Info** tab, confirm all `NSCameraUsageDescription`,  
   `NSFaceIDUsageDescription`, and `NSBluetoothAlwaysUsageDescription` keys are present
4. Set the **App Icon** source to `AppIcon` in Assets.xcassets

## Step 4 — Run on your iPhone
1. Connect your iPhone via USB
2. In Xcode, select your iPhone as the run destination
3. Press **▶ Run** (or ⌘R)
4. Trust the developer certificate on your iPhone:  
   **Settings → General → VPN & Device Management → your Apple ID → Trust**

---

## Step 5 — Share with others via TestFlight

1. Enroll at https://developer.apple.com/programs/ ($99/year)
2. In Xcode: **Product → Archive**
3. In the Organizer window: **Distribute App → TestFlight & App Store**
4. Follow the upload wizard
5. In [App Store Connect](https://appstoreconnect.apple.com):
   - Go to **TestFlight → Testers**
   - Add email addresses or create a public link
   - Testers install the free **TestFlight** app from the App Store, then tap your link

---

## Step 6 — App Store (public release)
Same as TestFlight upload, but choose **App Store** distribution and submit for Apple review.  
Review typically takes 1–3 days.

---

## Notes
- **APK is not possible** — this app uses Apple-only APIs (Secure Enclave, Face ID, CryptoKit).  
  It is iPhone-only by design.
- The Windows-side service (`PCUnlockService`) must also be running on the target PC.
- BLE range is approximately 10 metres.
