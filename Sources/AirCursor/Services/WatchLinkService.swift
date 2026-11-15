import CoreBluetooth
import CryptoKit
import Foundation
import AirCursorCore

/// The Apple Watch remote's Mac end: a Bluetooth LE peripheral the AirCursor watch app
/// connects to directly (no network, no iPhone in between).
///
/// Only a watch that paired with the one-time code shown in AirCursor can do anything: each
/// connection must answer a fresh challenge with the paired key, and every command is
/// authenticated (see `WatchProtocol.swift`). Both characteristics also require an
/// encrypted, bonded BLE link. Anything else is ignored. Callbacks arrive on the main queue.
final class WatchLinkService: NSObject, ObservableObject {
    enum Status: Equatable {
        case off
        /// Bluetooth is off, unsupported or not allowed.
        case unavailable(String)
        case advertising
        case connected
    }

    struct PairedWatch: Codable, Equatable, Identifiable {
        var id: String          // hex watch ID
        var key: Data
        var pairedAt: Date
    }

    @Published private(set) var status: Status = .off
    /// Non-nil while pairing: the code to type on the watch.
    @Published private(set) var pairingCode: String?
    @Published private(set) var pairingMessage: String?
    @Published private(set) var paired: [PairedWatch] = WatchLinkService.loadPaired()

    /// A verified command from a paired watch.
    var onCommand: ((WatchCommand) -> Void)?
    /// The last authenticated watch went away: release anything it was holding.
    var onWatchGone: (() -> Void)?
    /// A watch just authenticated (send it the current state).
    var onWatchReady: (() -> Void)?

    private var manager: CBPeripheralManager?
    private var commandCharacteristic: CBMutableCharacteristic?
    private var eventCharacteristic: CBMutableCharacteristic?
    private var serviceAdded = false
    private var wanted = false

    private struct Link {
        let central: CBCentral
        var challenge: Data?
        var session: WatchSession?
        var pairing: WatchPairing.MacSide?
    }
    private var links: [UUID: Link] = [:]
    private var outbox: [(Data, CBCentral)] = []
    private var pairingExpiry: Timer?
    private var pairingFailures = 0
    /// A code answers one hello only. Otherwise someone could learn it from the first answer
    /// and then try again with it.
    private var codeAnswered = false

    static let pairingWindow: TimeInterval = 180
    static let maxPairingFailures = 5
    private static let storeKey = "AirCursor.watchPairings"

    var isPaired: Bool { !paired.isEmpty }
    var hasAuthenticatedWatch: Bool { links.values.contains { $0.session != nil } }

    // MARK: Lifecycle

    func start() {
        guard !wanted else { return }
        wanted = true
        if let manager {
            peripheralManagerDidUpdateState(manager)
        } else {
            manager = CBPeripheralManager(delegate: self, queue: .main)
        }
    }

    func stop() {
        guard wanted else { return }
        wanted = false
        cancelPairing()
        dropAllLinks()
        manager?.stopAdvertising()
        // Take the service down too, so a watch that's still connected can't reach it.
        manager?.removeAllServices()
        serviceAdded = false
        status = .off
    }

    /// After sleep the radio may have been reset; start over cleanly.
    func restartAdvertising() {
        guard wanted, let manager, manager.state == .poweredOn else { return }
        manager.stopAdvertising()
        advertise()
    }

    // MARK: Pairing

    func beginPairing() {
        start()
        pairingFailures = 0
        pairingMessage = nil
        newCode()
        Diagnostics.log.notice("Watch pairing started")
    }

    func cancelPairing() {
        pairingExpiry?.invalidate()
        pairingExpiry = nil
        pairingCode = nil
        for id in links.keys { links[id]?.pairing = nil }
    }

    func forgetAll() {
        paired = []
        save()
        reauthenticateAll(except: nil)
        Diagnostics.log.notice("Forgot paired watches")
    }

    /// Ends every authenticated session (the key changed or was forgotten) and challenges
    /// each watch again; one whose key is gone is told to pair again.
    private func reauthenticateAll(except keep: UUID?) {
        let hadWatch = hasAuthenticatedWatch
        for id in links.keys where id != keep {
            links[id]?.session = nil
            issueChallenge(to: id)
        }
        if hadWatch, !hasAuthenticatedWatch { onWatchGone?() }
        updateStatus()
    }

    private func newCode() {
        pairingCode = WatchPairing.makeCode()
        codeAnswered = false
        for id in links.keys { links[id]?.pairing = nil }
        pairingExpiry?.invalidate()
        pairingExpiry = Timer.scheduledTimer(withTimeInterval: Self.pairingWindow, repeats: false) { [weak self] _ in
            self?.cancelPairing()
            self?.pairingMessage = "Pairing timed out. Start again when your watch is ready."
        }
    }

    private func pairingFailed(_ link: UUID, _ why: String) {
        Diagnostics.log.notice("Watch pairing attempt failed: \(why, privacy: .public)")
        send(WatchPairing.resultFrame(key: nil), to: link)
        links[link]?.pairing = nil
        pairingFailures += 1
        if pairingFailures >= Self.maxPairingFailures {
            cancelPairing()
            pairingMessage = "Too many wrong codes. Start pairing again."
        } else {
            // A code is good for one try: anyone guessing gets one chance in a million.
            newCode()
            pairingMessage = "That code didn’t match. Type the new code on your watch."
        }
    }

    // MARK: Events to the watch

    func send(_ event: WatchEvent) {
        for (id, link) in links where link.session != nil {
            guard var session = link.session else { continue }
            let frame = session.seal(event)
            links[id]?.session = session
            send(frame, to: id)
        }
    }

    private func send(_ frame: Data, to id: UUID) {
        guard let manager, let characteristic = eventCharacteristic, let central = links[id]?.central else { return }
        if frame.count > central.maximumUpdateValueLength {
            Diagnostics.log.error("Watch frame of \(frame.count) bytes exceeds \(central.maximumUpdateValueLength) bytes")
            return
        }
        if !outbox.isEmpty || !manager.updateValue(frame, for: characteristic, onSubscribedCentrals: [central]) {
            outbox.append((frame, central))
        }
    }

    // MARK: Internals

    private func advertise() {
        guard wanted, let manager, manager.state == .poweredOn, serviceAdded, !manager.isAdvertising else { return }
        manager.startAdvertising([
            CBAdvertisementDataServiceUUIDsKey: [CBUUID(string: WatchLink.serviceUUID)],
            CBAdvertisementDataLocalNameKey: "AirCursor",
        ])
    }

    private func setUpService(_ manager: CBPeripheralManager) {
        guard !serviceAdded else { return advertise() }
        let command = CBMutableCharacteristic(
            type: CBUUID(string: WatchLink.commandUUID),
            properties: [.write, .writeWithoutResponse],
            value: nil,
            permissions: [.writeEncryptionRequired])
        let event = CBMutableCharacteristic(
            type: CBUUID(string: WatchLink.eventUUID),
            properties: [.notify],
            value: nil,
            permissions: [.readEncryptionRequired])
        let service = CBMutableService(type: CBUUID(string: WatchLink.serviceUUID), primary: true)
        service.characteristics = [command, event]
        commandCharacteristic = command
        eventCharacteristic = event
        manager.add(service)
    }

    private func dropAllLinks() {
        let hadWatch = hasAuthenticatedWatch
        links.removeAll()
        outbox.removeAll()
        if hadWatch { onWatchGone?() }
        updateStatus()
    }

    private func updateStatus() {
        guard wanted else { status = .off; return }
        guard let manager else { return }
        switch manager.state {
        case .poweredOn: status = hasAuthenticatedWatch ? .connected : .advertising
        case .poweredOff: status = .unavailable("Bluetooth is off")
        case .unauthorized: status = .unavailable("Allow AirCursor to use Bluetooth in System Settings › Privacy & Security")
        case .unsupported: status = .unavailable("This Mac doesn’t support Bluetooth LE")
        default: status = .unavailable("Bluetooth isn’t ready")
        }
    }

    private func handle(_ frame: Data, from central: CBCentral) {
        let id = central.identifier
        if links[id] == nil { links[id] = Link(central: central) }
        guard let type = frame.first.flatMap(FrameType.init(rawValue:)) else { return }

        switch type {
        case .command:
            guard var session = links[id]?.session else { return }
            let command = session.openCommand(frame)
            links[id]?.session = session
            if let command { onCommand?(command) }

        case .authHello:
            guard let challenge = links[id]?.challenge else { return }
            links[id]?.challenge = nil
            do {
                let result = try WatchSession.verifyAuthHello(frame, challenge: challenge) { [paired] watchID in
                    let hex = watchID.hex
                    return paired.first { $0.id == hex }.map { SymmetricKey(data: $0.key) }
                }
                links[id]?.session = result.session
                send(result.reply, to: id)
                Diagnostics.log.notice("Apple Watch connected (\(result.watchID.hex.prefix(6), privacy: .public))")
                updateStatus()
                onWatchReady?()
            } catch WatchLinkError.unknownWatch {
                Diagnostics.log.notice("Unpaired watch tried to connect")
                send(WatchSession.authRejectedFrame, to: id)
                issueChallenge(to: id)
            } catch {
                Diagnostics.log.notice("Watch authentication failed")
                issueChallenge(to: id)
            }

        case .pairHello:
            guard let code = pairingCode else { return }
            guard !codeAnswered else { return pairingFailed(id, "code already used") }
            var side = WatchPairing.MacSide(code: code)
            do {
                let reply = try side.handleHello(frame)
                codeAnswered = true
                links[id]?.pairing = side
                send(reply, to: id)
            } catch {
                pairingFailed(id, "bad hello")
            }

        case .pairReveal:
            guard let side = links[id]?.pairing else { return }
            do {
                let key = try side.handleReveal(frame)
                let watchID = WatchPairing.watchID(for: key).hex
                // One watch at a time: the newly paired one replaces any other.
                paired = [PairedWatch(id: watchID, key: key.withUnsafeBytes { Data($0) }, pairedAt: Date())]
                save()
                send(WatchPairing.resultFrame(key: key), to: id)
                cancelPairing()
                pairingMessage = nil
                Diagnostics.log.notice("Apple Watch paired")
                // Other connections were authenticated with a key that no longer exists.
                reauthenticateAll(except: id)
                issueChallenge(to: id)
            } catch {
                pairingFailed(id, "wrong code")
            }

        default:
            return  // Mac → watch frame types; ignore.
        }
    }

    private func issueChallenge(to id: UUID) {
        let (frame, nonce) = WatchSession.challengeFrame()
        links[id]?.challenge = nonce
        send(frame, to: id)
    }

    private func save() {
        if let data = try? JSONEncoder().encode(paired) {
            UserDefaults.standard.set(data, forKey: Self.storeKey)
        }
    }

    private static func loadPaired() -> [PairedWatch] {
        guard let data = UserDefaults.standard.data(forKey: storeKey) else { return [] }
        return (try? JSONDecoder().decode([PairedWatch].self, from: data)) ?? []
    }
}

extension WatchLinkService: CBPeripheralManagerDelegate {
    func peripheralManagerDidUpdateState(_ peripheral: CBPeripheralManager) {
        Diagnostics.log.notice("Watch link Bluetooth state \(peripheral.state.rawValue, privacy: .public)")
        if peripheral.state == .poweredOn {
            if wanted { setUpService(peripheral) }
        } else {
            // The radio went away: every link is gone, and the service must be added again.
            serviceAdded = false
            dropAllLinks()
        }
        updateStatus()
    }

    func peripheralManager(_ peripheral: CBPeripheralManager, didAdd service: CBService, error: Error?) {
        if let error {
            Diagnostics.log.error("Watch link service failed: \(error.localizedDescription, privacy: .public)")
            status = .unavailable("Couldn’t start the watch link")
            return
        }
        serviceAdded = true
        advertise()
    }

    func peripheralManagerDidStartAdvertising(_ peripheral: CBPeripheralManager, error: Error?) {
        if let error {
            Diagnostics.log.error("Watch link advertising failed: \(error.localizedDescription, privacy: .public)")
        }
        if !wanted { peripheral.stopAdvertising() }
    }

    func peripheralManager(_ peripheral: CBPeripheralManager, central: CBCentral, didSubscribeTo characteristic: CBCharacteristic) {
        guard wanted, characteristic.uuid == eventCharacteristic?.uuid else { return }
        links[central.identifier] = Link(central: central)
        issueChallenge(to: central.identifier)
    }

    func peripheralManager(_ peripheral: CBPeripheralManager, central: CBCentral, didUnsubscribeFrom characteristic: CBCharacteristic) {
        guard characteristic.uuid == eventCharacteristic?.uuid else { return }
        let wasAuthenticated = links[central.identifier]?.session != nil
        links[central.identifier] = nil
        outbox.removeAll { $0.1.identifier == central.identifier }
        if wasAuthenticated {
            Diagnostics.log.notice("Apple Watch disconnected")
            if !hasAuthenticatedWatch { onWatchGone?() }
        }
        updateStatus()
    }

    func peripheralManager(_ peripheral: CBPeripheralManager, didReceiveWrite requests: [CBATTRequest]) {
        guard let first = requests.first else { return }
        guard wanted else {
            peripheral.respond(to: first, withResult: .writeNotPermitted)
            return
        }
        // A long write arrives as several requests with offsets; put each central's back together.
        var frames: [UUID: (CBCentral, Data)] = [:]
        for request in requests where request.characteristic.uuid == commandCharacteristic?.uuid {
            let value = request.value ?? Data()
            let id = request.central.identifier
            var entry = frames[id] ?? (request.central, Data())
            guard request.offset == entry.1.count, entry.1.count + value.count <= 512 else {
                peripheral.respond(to: first, withResult: .invalidOffset)
                return
            }
            entry.1.append(value)
            frames[id] = entry
        }
        peripheral.respond(to: first, withResult: .success)
        for (_, (central, frame)) in frames { handle(frame, from: central) }
    }

    func peripheralManagerIsReady(toUpdateSubscribers peripheral: CBPeripheralManager) {
        guard let characteristic = eventCharacteristic else { return }
        while let (frame, central) = outbox.first {
            guard peripheral.updateValue(frame, for: characteristic, onSubscribedCentrals: [central]) else { return }
            outbox.removeFirst()
        }
    }
}

private extension Data {
    var hex: String { map { String(format: "%02x", $0) }.joined() }
}
