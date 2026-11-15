import SwiftUI

@main
struct AirCursorWatchApp: App {
    @StateObject private var link = MacLink()
    @Environment(\.scenePhase) private var scenePhase

    var body: some Scene {
        WindowGroup {
            ContentView()
                .environmentObject(link)
        }
        .onChange(of: scenePhase) { _, phase in
            if phase == .active { link.resume() }
        }
    }
}

struct ContentView: View {
    @EnvironmentObject private var link: MacLink

    var body: some View {
        switch link.phase {
        case .ready:
            RemoteView()
        case .needsPairing, .pairing:
            PairingView()
        case .bluetoothUnavailable(let why):
            StatusView(symbol: "exclamationmark.triangle.fill", title: why, detail: nil)
        case .searching, .connecting, .authenticating:
            StatusView(symbol: "applewatch.radiowaves.left.and.right",
                       title: link.phase == .searching ? "Looking for your Mac" : "Connecting…",
                       detail: link.isPaired
                        ? "Keep AirCursor running on your Mac, close by."
                        : "In AirCursor on your Mac, open Settings › Apple Watch, turn it on and click Pair.")
        }
    }
}

struct StatusView: View {
    @EnvironmentObject private var link: MacLink
    let symbol: String
    let title: String
    let detail: String?

    var body: some View {
        ScrollView {
            VStack(spacing: 8) {
                Image(systemName: symbol)
                    .font(.title2)
                    .foregroundStyle(.tint)
                    .symbolEffect(.pulse)
                Text(title).font(.headline).multilineTextAlignment(.center)
                if let detail {
                    Text(detail).font(.footnote).foregroundStyle(.secondary).multilineTextAlignment(.center)
                }
                if let message = link.message {
                    Text(message).font(.footnote).foregroundStyle(.orange).multilineTextAlignment(.center)
                }
            }
            .padding(.horizontal, 4)
        }
    }
}
