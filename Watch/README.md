# AirCursor for Apple Watch

A one-screen remote for AirCursor on the Mac:

- **Double Tap** (index finger and thumb, Series 9 / Ultra 2 or newer) clicks where the
  pointer is. Tapping the big button does the same. The Mac binding is "Apple Watch Double
  Tap" in AirCursor's settings, so it can be a right click, drag, and so on.
- **Digital Crown** scrolls; in AirCursor's zoom mode it pinch-zooms around the pointer.
- **Buttons**: Talk (macOS Dictation), Send (Return), Pause / Resume head tracking,
  Scroll mode, Zoom mode.
- **Wrist taps** when a hover click fires, dictation starts or the Space changes.

## How it connects

Directly over Bluetooth LE: the Mac is the peripheral, the watch the central. No network,
no iPhone relay, no extra Mac entitlements. The wire protocol and its security live in
[`Sources/AirCursorCore/WatchProtocol.swift`](../Sources/AirCursorCore/WatchProtocol.swift),
compiled into both apps and unit-tested with the Mac package (`swift test`):

- Both characteristics require an encrypted, bonded BLE link.
- Pairing uses a one-time six-digit code shown on the Mac (commit–reveal over an X25519 key
  agreement; one guess per code, five tries per pairing window, 3-minute window).
- Every connection answers a fresh challenge with the paired key, and every command
  carries a counter and a MAC, so an unpaired device, a replay or a forged frame does
  nothing.
- If the watch disconnects, the Mac closes any pinch and releases any held button.

The remote is **off by default**: the Mac only advertises the Bluetooth service after you
turn on *Settings › Apple Watch › Use my Apple Watch as a remote*.

## Build and install

Needs Xcode with the watchOS SDK and the watch in Developer Mode (Settings › Privacy &
Security › Developer Mode on the watch; it appears after the watch has been connected to
Xcode once via its iPhone).

```bash
cd Watch
xcodebuild -project AirCursorWatch.xcodeproj -scheme AirCursorWatch \
  -destination 'platform=watchOS,name=<your watch>' -allowProvisioningUpdates \
  DEVELOPMENT_TEAM=<your team ID> build
```

Or open `Watch/AirCursorWatch.xcodeproj` in Xcode, pick your team under Signing, choose
the watch and Run. A free (personal) team works; its profile lasts 7 days.

## Use

1. On the Mac: AirCursor › Settings › Apple Watch → turn it on → **Pair Apple Watch…**
2. On the watch: open AirCursor, enter the code. If the watch or Mac asks to pair over
   Bluetooth, allow it.
3. The remote reconnects by itself whenever the app is open and the Mac is in range.

watchOS only keeps an app connected while it's on screen. To keep the remote up while the
wrist is down: watch Settings › General › Return to Clock › AirCursor → *After 1 hour*.
