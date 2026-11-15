import SwiftUI
import AirCursorCore

/// Settings for the Apple Watch remote: switch it on, pair with a code, tune it.
struct WatchSettingsView: View {
    @EnvironmentObject private var controller: AppController

    var body: some View {
        WatchSettingsForm(link: controller.watchLink)
    }
}

private struct WatchSettingsForm: View {
    @EnvironmentObject private var controller: AppController
    @ObservedObject var link: WatchLinkService

    var body: some View {
        Form {
            Section {
                Toggle("Use my Apple Watch as a remote", isOn: $controller.settings.watch.enabled)
                if controller.settings.watch.enabled {
                    Label(statusText, systemImage: statusSymbol)
                        .foregroundStyle(statusColor)
                }
            } footer: {
                Text("Install the AirCursor watch app, then pair once. Double Tap (pinch finger and thumb twice) clicks, the Digital Crown scrolls (or zooms in zoom mode), and your wrist taps when a hover click fires, dictation starts or the Space changes. The watch talks to this Mac directly over Bluetooth: nothing goes through the internet or your iPhone. Off by default, so the Mac only offers the remote's Bluetooth service when you turn this on.")
                    .font(.caption).foregroundStyle(.secondary)
            }

            if controller.settings.watch.enabled {
                Section("Pairing") {
                    if let code = link.pairingCode {
                        VStack(alignment: .leading, spacing: 8) {
                            Text("Open AirCursor on your watch, tap Pair, and enter:")
                            Text(code.map(String.init).joined(separator: " "))
                                .font(.system(size: 34, weight: .semibold, design: .monospaced))
                                .textSelection(.disabled)
                            Text("The code works once and expires in 3 minutes. If your watch asks to pair with this Mac over Bluetooth, allow it.")
                                .font(.caption).foregroundStyle(.secondary)
                        }
                        Button("Cancel") { link.cancelPairing() }
                    } else {
                        if let watch = link.paired.first {
                            LabeledContent("Paired watch") {
                                Text(watch.pairedAt.formatted(date: .abbreviated, time: .shortened))
                            }
                        }
                        HStack {
                            Button(link.isPaired ? "Pair a different watch…" : "Pair Apple Watch…") { link.beginPairing() }
                            if link.isPaired {
                                Button("Forget", role: .destructive) { link.forgetAll() }
                            }
                        }
                    }
                    if let message = link.pairingMessage {
                        Text(message).foregroundStyle(.orange)
                    }
                }

                Section("Remote") {
                    ActionPicker(trigger: .watchDoubleTap, action: Binding(
                        get: { controller.settings.actions[.watchDoubleTap] },
                        set: { controller.settings.actions[.watchDoubleTap] = $0 }))
                    LabeledSlider(title: "Digital Crown speed", value: $controller.settings.watch.crownSpeed, range: 0.25...3, step: 0.25,
                                  format: { String(format: "%.2g×", $0) })
                    Toggle("Tap my wrist for hover clicks, dictation and Space changes", isOn: $controller.settings.watch.haptics)
                    Text("The watch's buttons: Talk starts Dictation, Send presses Return, Pause pauses head tracking, Scroll and Zoom switch modes. Like the AirPods gestures, the remote only works while tracking is on (Pause still resumes it).")
                        .font(.caption).foregroundStyle(.secondary)
                }
            }
        }
        .formStyle(.grouped)
    }

    private var statusText: String {
        switch link.status {
        case .off: "Off"
        case .unavailable(let why): why
        case .advertising: link.isPaired ? "Waiting for your watch" : "Ready to pair"
        case .connected: "Watch connected"
        }
    }

    private var statusSymbol: String {
        switch link.status {
        case .connected: "applewatch.radiowaves.left.and.right"
        case .unavailable: "exclamationmark.triangle.fill"
        default: "applewatch"
        }
    }

    private var statusColor: Color {
        switch link.status {
        case .connected: .green
        case .unavailable: .orange
        default: .secondary
        }
    }
}
