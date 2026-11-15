import CryptoKit
import Foundation

// The Apple Watch remote's wire protocol, shared by the Mac app and the watch app (the
// watch target compiles this file directly, so it depends on nothing but Foundation and
// CryptoKit).
//
// Transport: Bluetooth LE only. The Mac is a peripheral with one service and two
// characteristics, both requiring an encrypted (bonded) link: the watch writes commands to
// `command` and gets events by subscribing to `event`.
//
// Security does not rely on the BLE link alone. A watch must first pair with a one-time
// six-digit code shown on the Mac (`WatchPairing`), which yields a 32-byte key both sides
// keep. Each connection then proves knowledge of that key with a fresh challenge, and every
// later frame carries a counter and a MAC under a per-connection session key, so frames
// can't be forged, replayed or reflected. A device that hasn't paired can't send anything
// the Mac acts on.

public enum WatchLink {
    public static let serviceUUID = "8B6E0001-4C1F-4F5A-9C1E-6A1C0A1C5001"
    public static let commandUUID = "8B6E0002-4C1F-4F5A-9C1E-6A1C0A1C5001"
    public static let eventUUID = "8B6E0003-4C1F-4F5A-9C1E-6A1C0A1C5001"

    public static let pairingCodeLength = 6
    public static let nonceLength = 16
    public static let tagLength = 8
    public static let watchIDLength = 8
}

// MARK: - Frame types

/// First byte of every frame.
public enum FrameType: UInt8, Sendable {
    // Watch → Mac
    case pairHello = 0x01
    case pairReveal = 0x02
    case authHello = 0x03
    case command = 0x10
    // Mac → watch
    case challenge = 0x81
    case pairChallenge = 0x82
    case pairResult = 0x83
    case authResult = 0x84
    case event = 0x90
}

/// What the watch asks the Mac to do.
public enum WatchCommand: Equatable, Sendable {
    /// Double Tap (or a tap on the big button): the `watchDoubleTap` trigger.
    case doubleTap
    /// One of the remote's fixed buttons.
    case button(WatchButton)
    /// Digital Crown turned; hundredths of a crown detent (positive = turned up / away).
    case crown(Int16)
    /// The crown stopped turning: close any pinch.
    case crownEnd
    /// Ask for a `state` event.
    case stateRequest

    var wire: (kind: UInt8, arg: Int16) {
        switch self {
        case .doubleTap: (1, 0)
        case .button(let b): (2, Int16(b.rawValue))
        case .crown(let d): (3, d)
        case .crownEnd: (4, 0)
        case .stateRequest: (5, 0)
        }
    }

    init?(kind: UInt8, arg: Int16) {
        switch kind {
        case 1: self = .doubleTap
        case 2:
            guard let b = UInt8(exactly: arg).flatMap(WatchButton.init(rawValue:)) else { return nil }
            self = .button(b)
        case 3: self = .crown(arg)
        case 4: self = .crownEnd
        case 5: self = .stateRequest
        default: return nil
        }
    }
}

/// The remote's buttons. Each does one fixed thing, so the watch's labels are always right.
public enum WatchButton: UInt8, CaseIterable, Sendable {
    case talk = 1, send, pause, scrollMode, zoomMode
}

/// Something the Mac tells the watch, mostly to tap the wrist.
public enum WatchEvent: Equatable, Sendable {
    case clicked
    case dictationStarted
    case spaceSwitched
    /// Tracking on/off and the current mode, so the remote's buttons show the truth.
    case state(tracking: Bool, mode: WatchMode)

    var wire: (kind: UInt8, arg: Int16) {
        switch self {
        case .clicked: (1, 0)
        case .dictationStarted: (2, 0)
        case .spaceSwitched: (3, 0)
        case .state(let tracking, let mode): (4, Int16(mode.rawValue) << 1 | (tracking ? 1 : 0))
        }
    }

    init?(kind: UInt8, arg: Int16) {
        switch kind {
        case 1: self = .clicked
        case 2: self = .dictationStarted
        case 3: self = .spaceSwitched
        case 4:
            guard let mode = WatchMode(rawValue: UInt8(truncatingIfNeeded: arg >> 1)) else { return nil }
            self = .state(tracking: arg & 1 == 1, mode: mode)
        default: return nil
        }
    }
}

public enum WatchMode: UInt8, Sendable {
    case pointer = 0, scroll, zoom
}

// MARK: - Pairing

public enum WatchLinkError: Error, Equatable {
    case malformed
    case badCode
    case badKey
    case unknownWatch
    case badTag
}

/// One-time pairing with a code shown on the Mac and typed on the watch.
///
/// 1. watch → `pairHello`: its X25519 key Pw and a commitment Cw = HMAC(code, "W"‖Pw‖Nw).
/// 2. Mac → `pairChallenge`: its key Pm, nonce Nm and Mm = HMAC(code, "M"‖Pm‖Pw‖Nm).
/// 3. The watch checks Mm (wrong code or a tampered key fails here) and only then reveals
///    → `pairReveal`: Nw. The Mac checks Cw.
///
/// The watch commits before the Mac says anything that depends on the code, and the watch
/// reveals only after the Mac proved the code, so neither side leaks enough for an offline
/// guess to help: an attacker in the middle gets one guess (1 in a million) per code, and the
/// Mac throws a code away after any failure. The long-term key is HKDF over the X25519
/// secret, salted with the code and bound to both public keys.
public enum WatchPairing {
    public static func makeCode() -> String {
        var g = SystemRandomNumberGenerator()
        return String(format: "%06d", Int.random(in: 0..<1_000_000, using: &g))
    }

    /// Accepts only exactly six ASCII digits.
    public static func isValidCode(_ code: String) -> Bool {
        code.count == WatchLink.pairingCodeLength && code.allSatisfy { $0.isASCII && $0.isNumber }
    }

    static func codeKey(_ code: String) -> SymmetricKey {
        SymmetricKey(data: SHA256.hash(data: Data("AirCursor pairing code \(code)".utf8)))
    }

    static func mac(_ key: SymmetricKey, _ parts: Data...) -> Data {
        var h = HMAC<SHA256>(key: key)
        for p in parts { h.update(data: p) }
        return Data(h.finalize())
    }

    static func deriveKey(shared: SharedSecret, code: String, watchPublic: Data, macPublic: Data) -> SymmetricKey {
        shared.hkdfDerivedSymmetricKey(
            using: SHA256.self,
            salt: Data(SHA256.hash(data: Data(code.utf8))),
            sharedInfo: Data("AirCursor watch link v1".utf8) + watchPublic + macPublic,
            outputByteCount: 32)
    }

    /// The watch's half of pairing.
    public struct WatchSide {
        let code: String
        let privateKey = Curve25519.KeyAgreement.PrivateKey()
        let nonce = WatchPairing.random(WatchLink.nonceLength)

        public init(code: String) { self.code = code }

        var publicKey: Data { privateKey.publicKey.rawRepresentation }

        /// Step 1.
        public func hello() -> Data {
            let commit = WatchPairing.mac(WatchPairing.codeKey(code), Data("W".utf8), publicKey, nonce)
            return Data([FrameType.pairHello.rawValue]) + publicKey + commit
        }

        /// Step 3: checks the Mac's proof and returns the reveal frame and the new key.
        public func handleChallenge(_ frame: Data) throws -> (reveal: Data, key: SymmetricKey) {
            let f = Data([UInt8](frame))
            guard f.count == 1 + 32 + WatchLink.nonceLength + 32, f.first == FrameType.pairChallenge.rawValue else {
                throw WatchLinkError.malformed
            }
            let macPublic = f.subdata(in: 1..<33)
            let macNonce = f.subdata(in: 33..<(33 + WatchLink.nonceLength))
            let proof = f.subdata(in: (33 + WatchLink.nonceLength)..<f.count)
            let expected = WatchPairing.mac(WatchPairing.codeKey(code), Data("M".utf8), macPublic, publicKey, macNonce)
            guard WatchPairing.constantTimeEqual(proof, expected) else { throw WatchLinkError.badCode }
            guard let peer = try? Curve25519.KeyAgreement.PublicKey(rawRepresentation: macPublic),
                  let shared = try? privateKey.sharedSecretFromKeyAgreement(with: peer) else {
                throw WatchLinkError.badKey
            }
            let key = WatchPairing.deriveKey(shared: shared, code: code, watchPublic: publicKey, macPublic: macPublic)
            return (Data([FrameType.pairReveal.rawValue]) + nonce, key)
        }
    }

    /// The Mac's half of pairing. Use one per code; discard it (and the code) on any error.
    public struct MacSide {
        let code: String
        let privateKey = Curve25519.KeyAgreement.PrivateKey()
        let nonce = WatchPairing.random(WatchLink.nonceLength)
        var watchPublic: Data?
        var watchCommit: Data?

        public init(code: String) { self.code = code }

        /// Step 2: answers a `pairHello`.
        public mutating func handleHello(_ frame: Data) throws -> Data {
            let f = Data([UInt8](frame))
            guard watchPublic == nil, f.count == 1 + 32 + 32, f.first == FrameType.pairHello.rawValue else {
                throw WatchLinkError.malformed
            }
            let pw = f.subdata(in: 1..<33)
            watchPublic = pw
            watchCommit = f.subdata(in: 33..<65)
            let pm = privateKey.publicKey.rawRepresentation
            let proof = WatchPairing.mac(WatchPairing.codeKey(code), Data("M".utf8), pm, pw, nonce)
            return Data([FrameType.pairChallenge.rawValue]) + pm + nonce + proof
        }

        /// Step 3 on the Mac: checks the watch's commitment; returns the new key.
        public func handleReveal(_ frame: Data) throws -> SymmetricKey {
            let f = Data([UInt8](frame))
            guard let pw = watchPublic, let commit = watchCommit,
                  f.count == 1 + WatchLink.nonceLength, f.first == FrameType.pairReveal.rawValue else {
                throw WatchLinkError.malformed
            }
            let expected = WatchPairing.mac(WatchPairing.codeKey(code), Data("W".utf8), pw, f.subdata(in: 1..<f.count))
            guard WatchPairing.constantTimeEqual(commit, expected) else { throw WatchLinkError.badCode }
            guard let peer = try? Curve25519.KeyAgreement.PublicKey(rawRepresentation: pw),
                  let shared = try? privateKey.sharedSecretFromKeyAgreement(with: peer) else {
                throw WatchLinkError.badKey
            }
            return WatchPairing.deriveKey(shared: shared, code: code, watchPublic: pw,
                                          macPublic: privateKey.publicKey.rawRepresentation)
        }
    }

    /// `pairResult` frame: success carries a MAC under the new key so the watch knows the Mac
    /// stored the same key.
    public static func resultFrame(key: SymmetricKey?) -> Data {
        guard let key else { return Data([FrameType.pairResult.rawValue, 0]) }
        return Data([FrameType.pairResult.rawValue, 1]) + mac(key, Data("paired".utf8)).prefix(WatchLink.tagLength)
    }

    public static func checkResult(_ frame: Data, key: SymmetricKey) -> Bool {
        let f = Data([UInt8](frame))
        guard f.count == 2 + WatchLink.tagLength, f.first == FrameType.pairResult.rawValue, f[f.startIndex + 1] == 1 else {
            return false
        }
        return constantTimeEqual(f.suffix(WatchLink.tagLength), mac(key, Data("paired".utf8)).prefix(WatchLink.tagLength))
    }

    /// Short public identifier of a paired watch, derived from its key.
    public static func watchID(for key: SymmetricKey) -> Data {
        mac(key, Data("watch id".utf8)).prefix(WatchLink.watchIDLength)
    }

    static func random(_ count: Int) -> Data {
        var g = SystemRandomNumberGenerator()
        return Data((0..<count).map { _ in UInt8.random(in: .min ... .max, using: &g) })
    }

    static func constantTimeEqual(_ a: Data, _ b: Data) -> Bool {
        guard a.count == b.count else { return false }
        var diff: UInt8 = 0
        for (x, y) in zip(a, b) { diff |= x ^ y }
        return diff == 0
    }
}

// MARK: - Connection authentication and frames

/// Proves a paired watch on each connection and protects every frame after that.
///
/// Mac → `challenge`: Nc. Watch → `authHello`: id‖Nw‖HMAC(K, "auth"‖Nc‖Nw‖id).
/// Session key Ks = HMAC(K, "session"‖Nc‖Nw); Mac → `authResult` with a MAC under Ks.
/// Frames: type‖counter(4)‖kind(1)‖arg(2)‖tag(8), tag = HMAC(Ks, direction‖header)[0..<8].
/// Counters must strictly increase, so nothing can be replayed within a connection, and a
/// new connection has a new Nc, so nothing from an old one is accepted.
public struct WatchSession: Sendable {
    public enum Role: Sendable { case mac, watch }

    let key: SymmetricKey
    let role: Role
    private var sendCounter: UInt32 = 0
    private var lastReceived: UInt32 = 0

    init(key: SymmetricKey, role: Role) {
        self.key = key
        self.role = role
    }

    public static func challengeFrame() -> (frame: Data, nonce: Data) {
        let n = WatchPairing.random(WatchLink.nonceLength)
        return (Data([FrameType.challenge.rawValue]) + n, n)
    }

    public static func challengeNonce(_ frame: Data) -> Data? {
        let f = Data([UInt8](frame))
        guard f.count == 1 + WatchLink.nonceLength, f.first == FrameType.challenge.rawValue else { return nil }
        return f.subdata(in: 1..<f.count)
    }

    /// Watch: answers the Mac's challenge with the paired key.
    public static func authHello(pairedKey: SymmetricKey, challenge: Data) -> (frame: Data, session: WatchSession) {
        let id = WatchPairing.watchID(for: pairedKey)
        let n = WatchPairing.random(WatchLink.nonceLength)
        let proof = WatchPairing.mac(pairedKey, Data("auth".utf8), challenge, n, id)
        let session = WatchSession(key: sessionKey(pairedKey, challenge, n), role: .watch)
        return (Data([FrameType.authHello.rawValue]) + id + n + proof, session)
    }

    /// Mac: verifies an `authHello`; `lookup` returns the key paired for a watch ID.
    public static func verifyAuthHello(_ frame: Data, challenge: Data,
                                       lookup: (Data) -> SymmetricKey?) throws -> (session: WatchSession, watchID: Data, reply: Data) {
        let f = Data([UInt8](frame))
        let idEnd = 1 + WatchLink.watchIDLength
        let nEnd = idEnd + WatchLink.nonceLength
        guard f.count == nEnd + 32, f.first == FrameType.authHello.rawValue else { throw WatchLinkError.malformed }
        let id = f.subdata(in: 1..<idEnd)
        let n = f.subdata(in: idEnd..<nEnd)
        guard let key = lookup(id) else { throw WatchLinkError.unknownWatch }
        let expected = WatchPairing.mac(key, Data("auth".utf8), challenge, n, id)
        guard WatchPairing.constantTimeEqual(f.subdata(in: nEnd..<f.count), expected) else { throw WatchLinkError.badTag }
        let session = WatchSession(key: sessionKey(key, challenge, n), role: .mac)
        let ok = Data([FrameType.authResult.rawValue, 1]) + WatchPairing.mac(session.key, Data("ok".utf8)).prefix(WatchLink.tagLength)
        return (session, id, ok)
    }

    /// Mac: tells a watch its key is unknown (forgotten on the Mac), so it should pair again.
    public static let authRejectedFrame = Data([FrameType.authResult.rawValue, 0])

    public enum AuthResult: Equatable { case accepted, rejected, invalid }

    /// Watch: checks the Mac's `authResult`.
    public func checkAuthResult(_ frame: Data) -> AuthResult {
        let f = Data([UInt8](frame))
        guard f.count >= 2, f.first == FrameType.authResult.rawValue else { return .invalid }
        if f[f.startIndex + 1] == 0 { return f.count == 2 ? .rejected : .invalid }
        guard f.count == 2 + WatchLink.tagLength else { return .invalid }
        let expected = WatchPairing.mac(key, Data("ok".utf8)).prefix(WatchLink.tagLength)
        return WatchPairing.constantTimeEqual(f.suffix(WatchLink.tagLength), expected) ? .accepted : .invalid
    }

    static func sessionKey(_ key: SymmetricKey, _ challenge: Data, _ nonce: Data) -> SymmetricKey {
        SymmetricKey(data: WatchPairing.mac(key, Data("session".utf8), challenge, nonce))
    }

    // Frames

    public static let frameLength = 1 + 4 + 1 + 2 + WatchLink.tagLength

    private func tag(_ header: Data, from sender: Role) -> Data {
        WatchPairing.mac(key, Data(sender == .watch ? "W".utf8 : "M".utf8), header).prefix(WatchLink.tagLength)
    }

    private mutating func seal(kind: UInt8, arg: Int16, type: FrameType) -> Data {
        sendCounter &+= 1
        var header = Data([type.rawValue])
        header.append(contentsOf: withUnsafeBytes(of: sendCounter.bigEndian, Array.init))
        header.append(kind)
        header.append(contentsOf: withUnsafeBytes(of: arg.bigEndian, Array.init))
        return header + tag(header, from: role)
    }

    private mutating func open(_ frame: Data, type: FrameType) -> (kind: UInt8, arg: Int16)? {
        let f = [UInt8](frame)
        guard f.count == Self.frameLength, f.first == type.rawValue else { return nil }
        let header = Data(f.prefix(8))
        let peer: Role = role == .mac ? .watch : .mac
        guard WatchPairing.constantTimeEqual(Data(f.suffix(WatchLink.tagLength)), tag(header, from: peer)) else { return nil }
        let counter = f[1..<5].reduce(UInt32(0)) { $0 << 8 | UInt32($1) }
        guard counter > lastReceived else { return nil }
        lastReceived = counter
        let arg = Int16(bitPattern: UInt16(f[6]) << 8 | UInt16(f[7]))
        return (f[5], arg)
    }

    /// Watch: a command frame.
    public mutating func seal(_ command: WatchCommand) -> Data {
        precondition(role == .watch)
        let w = command.wire
        return seal(kind: w.kind, arg: w.arg, type: .command)
    }

    /// Mac: an event frame.
    public mutating func seal(_ event: WatchEvent) -> Data {
        precondition(role == .mac)
        let w = event.wire
        return seal(kind: w.kind, arg: w.arg, type: .event)
    }

    /// Mac: verifies and decodes a command; nil if forged, replayed, reflected or unknown.
    public mutating func openCommand(_ frame: Data) -> WatchCommand? {
        guard role == .mac, let w = open(frame, type: .command) else { return nil }
        return WatchCommand(kind: w.kind, arg: w.arg)
    }

    /// Watch: verifies and decodes an event.
    public mutating func openEvent(_ frame: Data) -> WatchEvent? {
        guard role == .watch, let w = open(frame, type: .event) else { return nil }
        return WatchEvent(kind: w.kind, arg: w.arg)
    }
}

// MARK: - Digital Crown

/// Collects crown rotation into rate-limited deltas (hundredths of a detent).
public struct CrownAccumulator: Sendable {
    public var interval: TimeInterval
    private var pending: Double = 0
    private var lastSent: TimeInterval = -.infinity

    public init(interval: TimeInterval = 1.0 / 30.0) { self.interval = interval }

    public mutating func add(_ detents: Double) { pending += detents }

    /// The delta to send now, if any and if the rate limit allows.
    public mutating func take(now: TimeInterval) -> Int16? {
        guard now - lastSent >= interval else { return nil }
        let hundredths = (pending * 100).rounded(.towardZero)
        guard hundredths != 0 else { return nil }
        let clamped = max(min(hundredths, Double(Int16.max)), Double(Int16.min))
        pending -= clamped / 100
        lastSent = now
        return Int16(clamped)
    }

    public mutating func reset() { pending = 0 }
}
