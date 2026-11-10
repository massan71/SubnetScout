import Foundation
import Testing
@testable import ScanKit

@Suite struct BonjourParsingTests {
    @Test func parsesTXTRecords() {
        var bytes: [UInt8] = []
        for s in ["ty=HP LaserJet MFP M139w", "note=Living room", "flag"] {
            let u = Array(s.utf8); bytes.append(UInt8(u.count)); bytes += u
        }
        let txt = bytes.withUnsafeBufferPointer { BonjourScanner.parseTXT($0.baseAddress, length: $0.count) }
        #expect(txt["ty"] == "HP LaserJet MFP M139w")
        #expect(txt["note"] == "Living room")
        #expect(BonjourScanner.model(fromTXT: txt) == "HP LaserJet MFP M139w")
        // Length beyond the buffer: stops without reading out of bounds.
        let bad: [UInt8] = [200, 65, 66]
        #expect(bad.withUnsafeBufferPointer { BonjourScanner.parseTXT($0.baseAddress, length: $0.count) }.isEmpty)
    }

    @Test func unescapesDNSNames() {
        #expect(unescapeDNS("Printer\\032HP\\.home") == "Printer HP.home")
        #expect(unescapeDNS("Caf\\195\\169") == "Café")
    }

    @Test func bestNamePrefersReadableNames() {
        let d = BonjourDevice(ip: "x", names: ["FC9F5ED42C8A", "Kitchen", "Sonos Era 100 (Kitchen)"])
        #expect(d.bestName == "Kitchen")
        let tv = BonjourDevice(ip: "y", names: ["Smart-TV-Pro-e21d560af4e953b60014a2a5671cc975"], model: "Smart TV Pro")
        #expect(tv.bestName == "Smart TV Pro", "generated name → model")
    }

    @Test func kindFromBonjourServices() {
        func kind(_ services: [String], model: String? = nil, hostname: String = "x.lan") -> DeviceKind {
            ScanKit.Host(ip: "10.0.0.9", hostnames: [hostname], model: model, bonjourServices: services).kind
        }
        #expect(kind(["_ipp._tcp", "_http._tcp"]) == .printer)
        #expect(kind(["_googlecast._tcp"], hostname: "camera.da.letto.lan") == .tv, "Bonjour beats the name \"camera\"")
        #expect(kind(["_sonos._tcp", "_airplay._tcp"]) == .speaker)
        #expect(kind(["_shelly._tcp", "_http._tcp"]) == .iot)
        #expect(kind(["_companion-link._tcp"], model: "iPhone15,2") == .phone)
        #expect(kind(["_airplay._tcp"], model: "MacBookAir10,1") == .mac)
    }

    @Test func enrichMapsBonjourIncludingThisMac() {
        let local = NetworkInfo.interfaces().first?.ip ?? "10.0.0.2"
        let engine = ScanEngine(nmapPath: "/usr/bin/true")
        let hosts = engine.enrich([ScanKit.Host(ip: "10.0.0.50"), ScanKit.Host(ip: local)], arp: [:], bonjour: [
            "10.0.0.50": BonjourDevice(ip: "10.0.0.50", names: ["HP LaserJet MFP M140w (F62306)"], services: ["_ipp._tcp"], model: "HP LaserJet"),
            "127.0.0.1": BonjourDevice(ip: "127.0.0.1", names: ["Test MacBook Air"], services: ["_airplay._tcp"], model: "MacBookAir10,1"),
        ])
        let printer = hosts.first { $0.ip == "10.0.0.50" }
        #expect(printer?.displayName == "HP LaserJet MFP M140w (F62306)")
        #expect(printer?.kind == .printer)
        #expect(hosts.first { $0.ip == local }?.bonjourName == "Test MacBook Air")
    }

    /// Optional, on the real network: SUBNETSCOUT_LIVE=1 swift test --filter liveBonjour
    @Test(.enabled(if: ProcessInfo.processInfo.environment["SUBNETSCOUT_LIVE"] == "1"))
    func liveBonjour() {
        let found = BonjourScanner.discover(timeout: 4)
        for (ip, d) in found.sorted(by: { (IPv4.parse($0.key) ?? 0) < (IPv4.parse($1.key) ?? 0) }) {
            print("BONJOUR", ip, "|", d.bestName ?? "-", "|", d.model ?? "-", "|", d.services.prefix(4).joined(separator: ","))
        }
        #expect(!found.isEmpty)
    }
}
