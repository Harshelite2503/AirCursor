import CoreBluetooth
import CryptoKit
import Foundation
import WatchKit

/// The watch end of the AirCursor remote: a Bluetooth LE central that finds AirCursor on
/// the Mac, proves it's the paired watch, and sends authenticated commands. It talks to the
/// Mac directly; nothing goes through the iPhone or the network.
@MainActor
final class MacLink: NSObject, ObservableObject {
    enum Phase: Equatable {
        case bluetoothUnavailable(String)
        case searching
        case connecting
        /// Connected, waiting for the Mac's challenge / answer.
        case authenticating
        /// Connected to a Mac that doesn't know this watch: enter the code shown on the Mac.
        case needsPairing
        case pairing
        case ready
    }

    @Published private(set) var phase: Phase = .searching
    @Published private(set) var tracking = true
    @Published private(set) var mode: WatchMode = .pointer
    @Published private(set) var message: String?
    /// True when a key from an earlier pairing is stored.
    @Published private(set) var isPaired = KeyStore.load() != nil

    private var central: CBCentralManager!
    private var peripheral: CBPeripheral?
    private var commandCharacteristic: CBCharacteristic?
    private var eventCharacteristic: CBCharacteristic?
    private var challenge: Data?
    private var session: WatchSession?
    private var pairing: WatchPairing.WatchSide?
    private var pendingKey: SymmetricKey?
    private var crown = CrownAccumulator()
    private var crownTimer: Timer?
    /// The Mac is there but AirCursor's remote is switched off: wait for it to advertise
    /// again instead of reconnecting in a loop.
    private var serviceMissing = false

    private static let service = CBUUID(string: WatchLink.serviceUUID)
    private static let commandUUID = CBUUID(string: WatchLink.commandUUID)
    private static let eventUUID = CBUUID(string: WatchLink.eventUUID)
    private static let knownPeripheralKey = "AirCursor.macPeripheral"

    override init() {
        super.init()
        central = CBCentralManager(delegate: self, queue: .main)
    }

    // MARK: Commands

    func doubleTap() { send(.doubleTap, reliable: true) }

    func press(_ button: WatchButton) {
        guard phase == .ready else { return play(.failure) }
        send(.button(button), reliable: true)
    }

    /// Crown turned by `detents` (positive = up). Sent at most 30 times a second.
    func crownTurned(_ detents: Double) {
        guard phase == .ready else { return }
        crown.add(detents)
        flushCrown()
        if crownTimer == nil {
            crownTimer = Timer.scheduledTimer(withTimeInterval: crown.interval, repeats: true) { _ in
                MainActor.assumeIsolated { self.flushCrown() }
            }
        }
    }

    func crownStopped() {
        flushCrown()
        crownTimer?.invalidate()
        crownTimer = nil
        crown.reset()
        if phase == .ready { send(.crownEnd, reliable: false) }
    }

    private func flushCrown() {
        if let delta = crown.take(now: ProcessInfo.processInfo.systemUptime) {
            send(.crown(delta), reliable: false)
        }
    }

    private func send(_ command: WatchCommand, reliable: Bool) {
        guard var s = session, let p = peripheral, let c = commandCharacteristic, phase == .ready else { return }
        let frame = s.seal(command)
        session = s
        // Crown steps go without response (fast, droppable); everything else must arrive.
        let type: CBCharacteristicWriteType = !reliable && p.canSendWriteWithoutResponse ? .withoutResponse : .withResponse
        p.writeValue(frame, for: c, type: type)
    }

    // MARK: Pairing

    func pair(code: String) {
        guard WatchPairing.isValidCode(code), let p = peripheral, let c = commandCharacteristic,
              phase == .needsPairing || phase == .pairing else { return }
        message = nil
        let side = WatchPairing.WatchSide(code: code)
        pairing = side
        phase = .pairing
        p.writeValue(side.hello(), for: c, type: .withResponse)
    }

    /// Forgets the pairing on this watch (the Mac can forget it too, in AirCursor's settings).
    func forget() {
        KeyStore.delete()
        isPaired = false
        UserDefaults.standard.removeObject(forKey: Self.knownPeripheralKey)
        session = nil
        if peripheral?.state == .connected { phase = .needsPairing }
    }

    // MARK: Connection

    /// Called when the app comes to the front: reconnect if the link dropped meanwhile.
    func resume() {
        guard central.state == .poweredOn else { return }
        if let p = peripheral, p.state == .connected || p.state == .connecting { return }
        connect()
    }

    private func connect() {
        guard central.state == .poweredOn else { return }
        if let id = UserDefaults.standard.string(forKey: Self.knownPeripheralKey).flatMap(UUID.init(uuidString:)),
           let known = central.retrievePeripherals(withIdentifiers: [id]).first {
            attach(known)
        }
        // Also scan, in case the Mac's Bluetooth identity changed.
        if !central.isScanning {
            central.scanForPeripherals(withServices: [Self.service], options: nil)
        }
        if phase != .connecting { phase = .searching }
    }

    private func attach(_ p: CBPeripheral) {
        if let old = peripheral, old != p { central.cancelPeripheralConnection(old) }
        peripheral = p
        p.delegate = self
        phase = .connecting
        // No timeout: the connection completes whenever the Mac is back in range.
        central.connect(p, options: nil)
    }

    private func linkDropped() {
        session = nil
        challenge = nil
        pairing = nil
        commandCharacteristic = nil
        eventCharacteristic = nil
        crownTimer?.invalidate()
        crownTimer = nil
        crown.reset()
        guard central.state == .poweredOn else { return }
        if let p = peripheral, !serviceMissing {
            phase = .connecting
            central.connect(p, options: nil)
        } else {
            phase = .searching
        }
        if !central.isScanning { central.scanForPeripherals(withServices: [Self.service], options: nil) }
    }

    // MARK: Frames from the Mac

    private func received(_ frame: Data) {
        guard let type = frame.first.flatMap(FrameType.init(rawValue:)) else { return }
        switch type {
        case .challenge:
            guard let nonce = WatchSession.challengeNonce(frame) else { return }
            challenge = nonce
            session = nil
            if let key = KeyStore.load() {
                authenticate(key: key, challenge: nonce)
            } else if phase != .pairing {
                phase = .needsPairing
            }

        case .authResult:
            guard let s = session else { return }
            switch s.checkAuthResult(frame) {
            case .accepted:
                phase = .ready
                message = nil
                if let id = peripheral?.identifier.uuidString {
                    UserDefaults.standard.set(id, forKey: Self.knownPeripheralKey)
                }
                if central.isScanning { central.stopScan() }
                send(.stateRequest, reliable: true)
                play(.success)
            case .rejected:
                // This Mac forgot us (or it's another Mac): pair again.
                session = nil
                KeyStore.delete()
                isPaired = false
                phase = .needsPairing
                message = "This Mac doesn’t know this watch. Pair again."
            case .invalid:
                return
            }

        case .pairChallenge:
            guard let side = pairing, let p = peripheral, let c = commandCharacteristic else { return }
            do {
                let (reveal, key) = try side.handleChallenge(frame)
                pendingKey = key
                p.writeValue(reveal, for: c, type: .withResponse)
            } catch {
                pairingFailed()
            }

        case .pairResult:
            guard pairing != nil else { return }
            if let key = pendingKey, WatchPairing.checkResult(frame, key: key) {
                KeyStore.save(key)
                isPaired = true
                pairing = nil
                pendingKey = nil
                phase = .authenticating
                play(.success)
                // The Mac sends a new challenge next; we answer it with the new key.
            } else {
                pairingFailed()
            }

        case .event:
            guard var s = session else { return }
            let event = s.openEvent(frame)
            session = s
            if let event { handle(event) }

        default:
            return
        }
    }

    private func authenticate(key: SymmetricKey, challenge nonce: Data) {
        guard let p = peripheral, let c = commandCharacteristic else { return }
        let (frame, s) = WatchSession.authHello(pairedKey: key, challenge: nonce)
        session = s
        phase = .authenticating
        p.writeValue(frame, for: c, type: .withResponse)
    }

    private func pairingFailed() {
        pairing = nil
        pendingKey = nil
        phase = .needsPairing
        message = "That code didn’t match. Enter the new code from your Mac."
        play(.failure)
    }

    private func handle(_ event: WatchEvent) {
        switch event {
        case .clicked: play(.click)
        case .dictationStarted: play(.start)
        case .spaceSwitched: play(.directionUp)
        case .state(let tracking, let mode):
            self.tracking = tracking
            self.mode = mode
        }
    }

    private func play(_ haptic: WKHapticType) {
        WKInterfaceDevice.current().play(haptic)
    }
}

// MARK: - CoreBluetooth

extension MacLink: CBCentralManagerDelegate, CBPeripheralDelegate {
    nonisolated func centralManagerDidUpdateState(_ central: CBCentralManager) {
        MainActor.assumeIsolated {
            switch central.state {
            case .poweredOn: connect()
            case .poweredOff: phase = .bluetoothUnavailable("Turn on Bluetooth")
            case .unauthorized: phase = .bluetoothUnavailable("Allow Bluetooth for AirCursor in Settings › Privacy")
            case .unsupported: phase = .bluetoothUnavailable("Bluetooth LE isn’t supported")
            default: phase = .bluetoothUnavailable("Bluetooth isn’t ready")
            }
            if central.state != .poweredOn { session = nil }
        }
    }

    nonisolated func centralManager(_ central: CBCentralManager, didDiscover peripheral: CBPeripheral,
                                    advertisementData: [String: Any], rssi RSSI: NSNumber) {
        MainActor.assumeIsolated {
            // Already talking to a Mac (or on the way): leave it be.
            if let current = self.peripheral, current.state == .connected || current.state == .connecting,
               phase != .searching {
                return
            }
            attach(peripheral)
        }
    }

    nonisolated func centralManager(_ central: CBCentralManager, didConnect peripheral: CBPeripheral) {
        MainActor.assumeIsolated {
            guard peripheral == self.peripheral else { return central.cancelPeripheralConnection(peripheral) }
            phase = .authenticating
            peripheral.discoverServices([Self.service])
        }
    }

    nonisolated func centralManager(_ central: CBCentralManager, didFailToConnect peripheral: CBPeripheral, error: Error?) {
        MainActor.assumeIsolated {
            guard peripheral == self.peripheral else { return }
            linkDropped()
        }
    }

    nonisolated func centralManager(_ central: CBCentralManager, didDisconnectPeripheral peripheral: CBPeripheral, error: Error?) {
        MainActor.assumeIsolated {
            guard peripheral == self.peripheral else { return }
            linkDropped()
        }
    }

    nonisolated func peripheral(_ peripheral: CBPeripheral, didDiscoverServices error: Error?) {
        MainActor.assumeIsolated {
            guard let service = peripheral.services?.first(where: { $0.uuid == Self.service }) else {
                // AirCursor's remote is off (or this isn't AirCursor).
                serviceMissing = true
                return central.cancelPeripheralConnection(peripheral)
            }
            serviceMissing = false
            peripheral.discoverCharacteristics([Self.commandUUID, Self.eventUUID], for: service)
        }
    }

    nonisolated func peripheral(_ peripheral: CBPeripheral, didDiscoverCharacteristicsFor service: CBService, error: Error?) {
        MainActor.assumeIsolated {
            for c in service.characteristics ?? [] {
                if c.uuid == Self.commandUUID { commandCharacteristic = c }
                if c.uuid == Self.eventUUID { eventCharacteristic = c }
            }
            guard let events = eventCharacteristic, commandCharacteristic != nil else {
                return central.cancelPeripheralConnection(peripheral)
            }
            // Subscribing needs an encrypted link: the first time, watchOS asks to pair.
            peripheral.setNotifyValue(true, for: events)
        }
    }

    nonisolated func peripheral(_ peripheral: CBPeripheral, didModifyServices invalidatedServices: [CBService]) {
        MainActor.assumeIsolated {
            // AirCursor's remote was switched off on the Mac: start over (and wait for it).
            guard invalidatedServices.contains(where: { $0.uuid == Self.service }) else { return }
            serviceMissing = true
            central.cancelPeripheralConnection(peripheral)
        }
    }

    nonisolated func peripheral(_ peripheral: CBPeripheral, didUpdateNotificationStateFor characteristic: CBCharacteristic, error: Error?) {
        MainActor.assumeIsolated {
            if let error {
                message = "Couldn’t connect securely: \(error.localizedDescription)"
                central.cancelPeripheralConnection(peripheral)
            }
        }
    }

    nonisolated func peripheral(_ peripheral: CBPeripheral, didUpdateValueFor characteristic: CBCharacteristic, error: Error?) {
        MainActor.assumeIsolated {
            guard error == nil, characteristic.uuid == Self.eventUUID, let value = characteristic.value else { return }
            received(value)
        }
    }

    nonisolated func peripheral(_ peripheral: CBPeripheral, didWriteValueFor characteristic: CBCharacteristic, error: Error?) {
        MainActor.assumeIsolated {
            if let error { message = "Send failed: \(error.localizedDescription)" }
        }
    }
}

// MARK: - Key storage (the watch's keychain)

enum KeyStore {
    private static let query: [String: Any] = [
        kSecClass as String: kSecClassGenericPassword,
        kSecAttrService as String: "io.github.m-afham.AirCursor.watch-link",
        kSecAttrAccount as String: "paired-mac",
    ]

    static func load() -> SymmetricKey? {
        var q = query
        q[kSecReturnData as String] = true
        var out: AnyObject?
        guard SecItemCopyMatching(q as CFDictionary, &out) == errSecSuccess, let data = out as? Data else { return nil }
        return SymmetricKey(data: data)
    }

    static func save(_ key: SymmetricKey) {
        delete()
        var q = query
        q[kSecValueData as String] = key.withUnsafeBytes { Data($0) }
        q[kSecAttrAccessible as String] = kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly
        SecItemAdd(q as CFDictionary, nil)
    }

    static func delete() {
        SecItemDelete(query as CFDictionary)
    }
}
