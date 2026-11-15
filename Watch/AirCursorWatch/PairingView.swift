import SwiftUI

/// Enter the six-digit code AirCursor shows on the Mac.
struct PairingView: View {
    @EnvironmentObject private var link: MacLink
    @State private var code = ""

    private let rows = [["1", "2", "3"], ["4", "5", "6"], ["7", "8", "9"], ["⌫", "0", "✓"]]

    var body: some View {
        VStack(spacing: 3) {
            Text(display)
                .font(.system(.title3, design: .monospaced).weight(.semibold))
                .foregroundStyle(link.phase == .pairing ? .secondary : .primary)
            if let message = link.message {
                Text(message).font(.system(size: 11)).foregroundStyle(.orange)
                    .lineLimit(2).multilineTextAlignment(.center)
            } else {
                Text(link.phase == .pairing ? "Pairing…" : "Code shown on your Mac")
                    .font(.system(size: 11)).foregroundStyle(.secondary)
            }
            Grid(horizontalSpacing: 3, verticalSpacing: 3) {
                ForEach(rows, id: \.self) { row in
                    GridRow {
                        ForEach(row, id: \.self) { key in
                            Button { tap(key) } label: {
                                Text(key).font(.body.weight(.medium)).frame(maxWidth: .infinity, minHeight: 26)
                            }
                            .buttonStyle(.bordered)
                            .tint(key == "✓" ? .green : nil)
                            .disabled(link.phase == .pairing || (key == "✓" && code.count < 6))
                        }
                    }
                }
            }
        }
        .onChange(of: link.message) { _, message in
            if message != nil { code = "" }
        }
    }

    private var display: String {
        let typed = code.map(String.init)
        return (typed + Array(repeating: "–", count: 6 - typed.count)).joined(separator: " ")
    }

    private func tap(_ key: String) {
        switch key {
        case "⌫": if !code.isEmpty { code.removeLast() }
        case "✓": link.pair(code: code)
        default: if code.count < 6 { code += key }
        }
    }
}
