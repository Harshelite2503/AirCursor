import SwiftUI

/// The one-screen remote: a big Click button (Double Tap presses it), five buttons, and
/// the Digital Crown for scrolling or, in zoom mode, zooming.
struct RemoteView: View {
    @EnvironmentObject private var link: MacLink
    @State private var crown = 0.0
    @State private var lastCrown = 0.0
    @State private var showingOptions = false
    @FocusState private var crownFocused: Bool

    var body: some View {
        VStack(spacing: 6) {
            Button {
                link.doubleTap()
            } label: {
                VStack(spacing: 2) {
                    Image(systemName: "cursorarrow.click.2").font(.title2)
                    Text(statusLine).font(.caption2).foregroundStyle(.secondary).lineLimit(1)
                }
                .frame(maxWidth: .infinity, maxHeight: .infinity)
            }
            .buttonStyle(.borderedProminent)
            .tint(link.tracking ? .blue : .gray)
            // Double Tap (finger and thumb) presses this button.
            .handGestureShortcut(.primaryAction)
            .accessibilityLabel("Click")

            Grid(horizontalSpacing: 6, verticalSpacing: 6) {
                GridRow {
                    small("mic.fill", "Talk", .talk)
                    small("return", "Send", .send)
                    small(link.tracking ? "pause.fill" : "play.fill", link.tracking ? "Pause" : "Resume", .pause,
                          active: !link.tracking)
                }
                GridRow {
                    small("arrow.up.and.down", "Scroll", .scrollMode, active: link.mode == .scroll)
                    small("plus.magnifyingglass", "Zoom", .zoomMode, active: link.mode == .zoom)
                    Button {
                        showingOptions = true
                    } label: {
                        Image(systemName: "ellipsis").frame(maxWidth: .infinity, minHeight: 30)
                    }
                    .accessibilityLabel("Options")
                }
            }
        }
        .focusable()
        .focused($crownFocused)
        .onAppear { crownFocused = true }
        // Haptic detents at each whole step, but the continuous offset is what's sent, so
        // scrolling is smooth between detents.
        .digitalCrownRotation(detent: $crown, from: -1_000_000, through: 1_000_000, by: 1,
                              sensitivity: .medium, isContinuous: true, isHapticFeedbackEnabled: true,
                              onChange: { event in
                                  link.crownTurned(event.offset - lastCrown)
                                  lastCrown = event.offset
                              },
                              onIdle: { link.crownStopped() })
        .sheet(isPresented: $showingOptions) { OptionsView() }
    }

    private var statusLine: String {
        if !link.tracking { return "Paused" }
        switch link.mode {
        case .pointer: return "Crown scrolls"
        case .scroll: return "Scroll mode"
        case .zoom: return "Crown zooms"
        }
    }

    private func small(_ symbol: String, _ label: String, _ button: WatchButton, active: Bool = false) -> some View {
        Button {
            link.press(button)
        } label: {
            Image(systemName: symbol).frame(maxWidth: .infinity, minHeight: 30)
        }
        .tint(active ? .orange : nil)
        .accessibilityLabel(label)
    }
}

struct OptionsView: View {
    @EnvironmentObject private var link: MacLink
    @Environment(\.dismiss) private var dismiss

    var body: some View {
        ScrollView {
            VStack(alignment: .leading, spacing: 10) {
                Text("Double Tap clicks where the pointer is. Turn the crown to scroll; in zoom mode it zooms. Talk starts Dictation, Send presses Return.")
                    .font(.footnote)
                Button("Forget this Mac", role: .destructive) {
                    link.forget()
                    dismiss()
                }
            }
        }
    }
}
