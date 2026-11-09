import Foundation

/// Dati raccolti «toccando» la rete locale: tabella ARP e router UPnP.
///
/// macOS può negare all'app il permesso «Rete locale» (e lo fa in silenzio);
/// il helper root, come daemon di sistema, non è soggetto a quel permesso.
/// Per questo la sonda può girare sia nell'app sia nel helper.
public struct NetworkProbe: Codable, Sendable, Equatable {
    public var arp: [String: String]
    public var upnpGateways: [UPnPGateway]
    public var upnpError: String?
    /// "helper" o "app": chi ha eseguito la sonda.
    public var source: String

    public init(arp: [String: String], upnpGateways: [UPnPGateway], upnpError: String?, source: String) {
        self.arp = arp
        self.upnpGateways = upnpGateways
        self.upnpError = upnpError
        self.source = source
    }

    /// true se la tabella ARP è vuota pur essendoci un gateway: segno che macOS
    /// blocca l'accesso alla rete locale a chi ha eseguito la sonda.
    public var looksBlocked: Bool { arp.isEmpty && NetworkInfo.defaultGateway() != nil }

    public static func run(source: String, inspectUPnP: Bool = true) async -> NetworkProbe {
        let arp = NetworkInfo.arpTable()
        let gateway = NetworkInfo.defaultGateway()
        var probe = NetworkProbe(arp: arp, upnpGateways: [], upnpError: nil, source: source)
        if arp.isEmpty, gateway != nil {
            probe.upnpError = ScanEngine.localNetworkMessage
            return probe
        }
        guard inspectUPnP else { return probe }
        do {
            probe.upnpGateways = try await UPnPInspector.discover(extraTargets: [gateway].compactMap { $0 })
        } catch {
            probe.upnpError = error.localizedDescription
        }
        return probe
    }
}
