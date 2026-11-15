import CryptoKit
import XCTest
@testable import AirCursorCore

final class WatchProtocolTests: XCTestCase {
    // MARK: Pairing

    private func pair(macCode: String, watchCode: String) throws -> (mac: SymmetricKey, watch: SymmetricKey) {
        let watch = WatchPairing.WatchSide(code: watchCode)
        var mac = WatchPairing.MacSide(code: macCode)
        let challenge = try mac.handleHello(watch.hello())
        let (reveal, watchKey) = try watch.handleChallenge(challenge)
        let macKey = try mac.handleReveal(reveal)
        return (macKey, watchKey)
    }

    func testPairingWithTheSameCodeAgreesOnAKey() throws {
        let (mac, watch) = try pair(macCode: "042917", watchCode: "042917")
        XCTAssertEqual(mac, watch)
        XCTAssertEqual(WatchPairing.watchID(for: mac), WatchPairing.watchID(for: watch))
        XCTAssertTrue(WatchPairing.checkResult(WatchPairing.resultFrame(key: mac), key: watch))
    }

    func testPairingWithAWrongCodeFailsBeforeTheWatchRevealsAnything() {
        XCTAssertThrowsError(try pair(macCode: "123456", watchCode: "123457")) { error in
            XCTAssertEqual(error as? WatchLinkError, .badCode)
        }
    }

    func testEachPairingMakesADifferentKey() throws {
        let a = try pair(macCode: "000001", watchCode: "000001").mac
        let b = try pair(macCode: "000001", watchCode: "000001").mac
        XCTAssertNotEqual(a, b)
    }

    func testTamperedMacKeyIsRejectedByTheWatch() throws {
        let watch = WatchPairing.WatchSide(code: "555555")
        var mac = WatchPairing.MacSide(code: "555555")
        var challenge = try mac.handleHello(watch.hello())
        challenge[5] ^= 0xFF  // someone swaps the Mac's public key in flight
        XCTAssertThrowsError(try watch.handleChallenge(challenge))
    }

    func testTamperedWatchKeyIsRejectedByTheMac() throws {
        // An attacker replaces the watch's key but can't make a matching commitment.
        let watch = WatchPairing.WatchSide(code: "555555")
        var hello = watch.hello()
        hello[3] ^= 0x01
        var mac = WatchPairing.MacSide(code: "555555")
        let challenge = try mac.handleHello(hello)
        // The real watch sees a proof bound to a different key than its own and stops.
        XCTAssertThrowsError(try watch.handleChallenge(challenge))
    }

    func testWrongRevealIsRejectedByTheMac() throws {
        let watch = WatchPairing.WatchSide(code: "314159")
        var mac = WatchPairing.MacSide(code: "314159")
        _ = try mac.handleHello(watch.hello())
        let bogus = Data([FrameType.pairReveal.rawValue]) + Data(repeating: 7, count: WatchLink.nonceLength)
        XCTAssertThrowsError(try mac.handleReveal(bogus)) { XCTAssertEqual($0 as? WatchLinkError, .badCode) }
    }

    func testMacSideAcceptsOnlyOneHello() throws {
        var mac = WatchPairing.MacSide(code: "111111")
        _ = try mac.handleHello(WatchPairing.WatchSide(code: "111111").hello())
        XCTAssertThrowsError(try mac.handleHello(WatchPairing.WatchSide(code: "111111").hello()))
    }

    func testMalformedPairingFramesThrowInsteadOfCrashing() {
        var mac = WatchPairing.MacSide(code: "111111")
        for frame in [Data(), Data([0x01]), Data([0x02, 1, 2]), Data(repeating: 0x01, count: 64)] {
            XCTAssertThrowsError(try mac.handleHello(frame))
            XCTAssertThrowsError(try mac.handleReveal(frame))
            XCTAssertThrowsError(try WatchPairing.WatchSide(code: "111111").handleChallenge(frame))
        }
    }

    func testCodes() {
        for _ in 0..<50 { XCTAssertTrue(WatchPairing.isValidCode(WatchPairing.makeCode())) }
        XCTAssertFalse(WatchPairing.isValidCode("12345"))
        XCTAssertFalse(WatchPairing.isValidCode("12345a"))
        XCTAssertFalse(WatchPairing.isValidCode("１２３４５６"))  // full-width digits
    }

    // MARK: Connection

    private func connect(_ key: SymmetricKey) throws -> (mac: WatchSession, watch: WatchSession) {
        let (_, nonce) = WatchSession.challengeFrame()
        let (hello, watch) = WatchSession.authHello(pairedKey: key, challenge: nonce)
        let id = WatchPairing.watchID(for: key)
        let result = try WatchSession.verifyAuthHello(hello, challenge: nonce) { $0 == id ? key : nil }
        XCTAssertEqual(result.watchID, id)
        XCTAssertEqual(watch.checkAuthResult(result.reply), .accepted)
        return (result.session, watch)
    }

    func testPairedWatchAuthenticatesAndCommandsRoundTrip() throws {
        let key = SymmetricKey(size: .bits256)
        var (mac, watch) = try connect(key)
        let commands: [WatchCommand] = [.doubleTap, .crown(-250), .crown(.max), .crownEnd, .stateRequest]
            + WatchButton.allCases.map { .button($0) }
        for c in commands {
            let frame = watch.seal(c)
            XCTAssertEqual(frame.count, WatchSession.frameLength)
            XCTAssertLessThanOrEqual(frame.count, 20, "must fit the smallest BLE write")
            XCTAssertEqual(mac.openCommand(frame), c)
        }
        let events: [WatchEvent] = [.clicked, .dictationStarted, .spaceSwitched,
                                    .state(tracking: true, mode: .zoom), .state(tracking: false, mode: .pointer)]
        for e in events { XCTAssertEqual(watch.openEvent(mac.seal(e)), e) }
    }

    func testChallengeFrameRoundTrip() {
        let (frame, nonce) = WatchSession.challengeFrame()
        XCTAssertEqual(WatchSession.challengeNonce(frame), nonce)
        XCTAssertNil(WatchSession.challengeNonce(Data([0x81, 1])))
    }

    func testUnpairedDeviceCannotAuthenticate() {
        let paired = SymmetricKey(size: .bits256)
        let stranger = SymmetricKey(size: .bits256)
        let (_, nonce) = WatchSession.challengeFrame()
        let (hello, _) = WatchSession.authHello(pairedKey: stranger, challenge: nonce)
        let pairedID = WatchPairing.watchID(for: paired)
        XCTAssertThrowsError(try WatchSession.verifyAuthHello(hello, challenge: nonce) { $0 == pairedID ? paired : nil }) {
            XCTAssertEqual($0 as? WatchLinkError, .unknownWatch)
        }
        // Even claiming the paired watch's ID doesn't help without its key.
        var forged = hello
        forged.replaceSubrange(1..<(1 + WatchLink.watchIDLength), with: pairedID)
        XCTAssertThrowsError(try WatchSession.verifyAuthHello(forged, challenge: nonce) { $0 == pairedID ? paired : nil }) {
            XCTAssertEqual($0 as? WatchLinkError, .badTag)
        }
    }

    func testAuthHelloForAnOldChallengeIsRejected() {
        let key = SymmetricKey(size: .bits256)
        let (_, old) = WatchSession.challengeFrame()
        let (_, fresh) = WatchSession.challengeFrame()
        let (hello, _) = WatchSession.authHello(pairedKey: key, challenge: old)
        XCTAssertThrowsError(try WatchSession.verifyAuthHello(hello, challenge: fresh) { _ in key })
    }

    func testForgedReplayedAndReflectedFramesAreRejected() throws {
        let key = SymmetricKey(size: .bits256)
        var (mac, watch) = try connect(key)
        let click = watch.seal(.doubleTap)
        XCTAssertEqual(mac.openCommand(click), .doubleTap)
        XCTAssertNil(mac.openCommand(click), "replay")

        var tampered = watch.seal(.crown(10))
        tampered[7] ^= 0x40
        XCTAssertNil(mac.openCommand(tampered), "tampered argument")

        // A frame from another connection (different session key) is useless.
        var (_, otherWatch) = try connect(key)
        XCTAssertNil(mac.openCommand(otherWatch.seal(.doubleTap)))

        // The Mac's own event frame can't be bounced back as a command.
        var event = mac.seal(.clicked)
        event[0] = FrameType.command.rawValue
        XCTAssertNil(mac.openCommand(event))

        for junk in [Data(), Data([0x10]), Data(repeating: 0x10, count: WatchSession.frameLength)] {
            XCTAssertNil(mac.openCommand(junk))
            XCTAssertNil(watch.openEvent(junk))
        }
        // Still works after all that.
        XCTAssertEqual(mac.openCommand(watch.seal(.button(.talk))), .button(.talk))
    }

    func testRejectedAuthResult() throws {
        let (_, watch) = try connect(SymmetricKey(size: .bits256))
        XCTAssertEqual(watch.checkAuthResult(WatchSession.authRejectedFrame), .rejected)
        XCTAssertEqual(watch.checkAuthResult(Data([FrameType.authResult.rawValue, 1]) + Data(count: 8)), .invalid)
    }

    func testUnknownCommandKindsAreIgnored() {
        XCTAssertNil(WatchCommand(kind: 99, arg: 0))
        XCTAssertNil(WatchCommand(kind: 2, arg: 99))   // no such button
        XCTAssertNil(WatchCommand(kind: 2, arg: -1))
        XCTAssertNil(WatchEvent(kind: 4, arg: 3 << 1))  // no such mode
    }

    // MARK: Crown

    func testCrownAccumulatorRateLimitsAndKeepsRemainders() {
        var crown = CrownAccumulator(interval: 0.05)
        crown.add(0.004)
        XCTAssertNil(crown.take(now: 0), "less than a hundredth")
        crown.add(0.5)
        XCTAssertEqual(crown.take(now: 0), 50)
        crown.add(0.3)
        XCTAssertNil(crown.take(now: 0.02), "rate limited")
        crown.add(-0.1)
        XCTAssertEqual(crown.take(now: 0.06), 20)
        crown.add(1000)
        XCTAssertEqual(crown.take(now: 1), .max)
        crown.reset()
        XCTAssertNil(crown.take(now: 2))
    }

    // MARK: Settings and bindings

    func testWatchDefaults() {
        let s = AppSettings()
        XCTAssertFalse(s.watch.enabled, "the Mac doesn't advertise over Bluetooth unless asked")
        XCTAssertEqual(s.actions[.watchDoubleTap], .leftClick)
        XCTAssertNil(Trigger.watchDoubleTap.headGesture)
        XCTAssertFalse(Trigger.watchDoubleTap.isStem)
        XCTAssertEqual(WatchButton.talk.action, .dictate)
        XCTAssertEqual(WatchButton.send.action, .pressReturn)
        XCTAssertEqual(WatchButton.pause.action, .toggleTracking)
        XCTAssertEqual(WatchButton.scrollMode.action, .toggleScrollMode)
        XCTAssertEqual(WatchButton.zoomMode.action, .toggleZoomMode)
    }

    func testOlderSettingsGainTheWatchRemoteSwitchedOff() throws {
        let v8 = #"{"version":8,"actions":{"nod":"rightClick"}}"#
        let s = try JSONDecoder().decode(AppSettings.self, from: Data(v8.utf8)).migrated()
        XCTAssertEqual(s.watch, WatchSettings())
        XCTAssertEqual(s.actions[.watchDoubleTap], .leftClick)
        XCTAssertEqual(s.actions[.nod], .rightClick)
    }

    func testWatchSettingsDecodeLenientlyAndRoundTrip() throws {
        let odd = #"{"watch":{"enabled":true,"crownSpeed":"fast"},"actions":{"watchDoubleTap":"rightClick"}}"#
        let s = try JSONDecoder().decode(AppSettings.self, from: Data(odd.utf8))
        XCTAssertTrue(s.watch.enabled)
        XCTAssertEqual(s.watch.crownSpeed, WatchSettings().crownSpeed)
        XCTAssertTrue(s.watch.haptics)
        XCTAssertEqual(s.actions[.watchDoubleTap], .rightClick)
        XCTAssertEqual(try JSONDecoder().decode(AppSettings.self, from: JSONEncoder().encode(s)), s)
    }
}

final class CrownGlideTests: XCTestCase {
    func testGlideDeliversEverythingSmoothlyAndFinishes() {
        var glide = CrownGlide()
        glide.add(100)
        var total = 0.0
        var steps: [Double] = []
        for _ in 0..<60 {
            let s = glide.step(dt: 1.0 / 120.0, epsilon: 0.5)
            steps.append(s)
            total += s
        }
        XCTAssertEqual(total, 100, accuracy: 1e-9)
        XCTAssertEqual(glide.pending, 0)
        XCTAssertLessThan(steps[0], 20, "spread over several frames")
        XCTAssertEqual(glide.step(dt: 1.0 / 120.0, epsilon: 0.5), 0)
    }

    func testGlideHandlesReversalsAndReset() {
        var glide = CrownGlide()
        glide.add(10)
        glide.add(-25)
        XCTAssertLessThan(glide.step(dt: 1, epsilon: 0.01), 0)
        glide.add(3)
        glide.reset()
        XCTAssertEqual(glide.step(dt: 0.01, epsilon: 0.01), 0)
        glide.add(1)
        XCTAssertEqual(glide.step(dt: -1, epsilon: 0.01), 0, "a clock hiccup doesn't explode")
    }
}
