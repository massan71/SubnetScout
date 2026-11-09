import Foundation

/// Lookup del produttore dal MAC usando il database OUI fornito con nmap
/// (`share/nmap/nmap-mac-prefixes`), così non serve distribuirne uno.
public final class MACVendorDB: Sendable {
    private let prefixes: [String: String]

    public init(prefixes: [String: String]) {
        self.prefixes = prefixes
    }

    public convenience init(nmapPath: String) {
        let base = URL(fileURLWithPath: nmapPath).resolvingSymlinksInPath()
            .deletingLastPathComponent().deletingLastPathComponent()
        let candidates = [
            base.appending(path: "share/nmap/nmap-mac-prefixes"),
            URL(fileURLWithPath: "/opt/homebrew/share/nmap/nmap-mac-prefixes"),
            URL(fileURLWithPath: "/usr/local/share/nmap/nmap-mac-prefixes"),
        ]
        var map: [String: String] = [:]
        if let url = candidates.first(where: { FileManager.default.fileExists(atPath: $0.path) }),
           let text = try? String(contentsOf: url, encoding: .utf8) {
            for line in text.split(separator: "\n") where !line.hasPrefix("#") {
                guard let space = line.firstIndex(of: " ") else { continue }
                map[String(line[..<space]).uppercased()] = String(line[line.index(after: space)...])
            }
        }
        self.init(prefixes: map)
    }

    public var isEmpty: Bool { prefixes.isEmpty }

    /// Restituisce il produttore, o "MAC privato (randomizzato)" per gli indirizzi
    /// amministrati localmente tipici di iPhone/Android con "indirizzo privato Wi-Fi".
    public func vendor(for mac: String) -> String? {
        let hex = mac.replacingOccurrences(of: ":", with: "").uppercased()
        guard hex.count == 12 else { return nil }
        // Prefissi più lunghi prima (MA-S 9, MA-M 7, MA-L 6).
        for len in [9, 7, 6] {
            if let v = prefixes[String(hex.prefix(len))] { return v }
        }
        if isLocallyAdministered(mac) { return "MAC privato (randomizzato)" }
        return nil
    }

    public func isLocallyAdministered(_ mac: String) -> Bool {
        guard let first = UInt8(mac.prefix(2), radix: 16) else { return false }
        return first & 0x02 != 0
    }
}
