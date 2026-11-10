import Foundation

/// Data collected by "touching" the local network: ARP table and UPnP routers.
///
/// macOS can deny the app the Local Network permission (and does so silently);
/// the root helper, as a system daemon, is not subject to that permission.
/// That is why the probe can run both in the app and in the helper.
public struct NetworkProbe: Codable, Sendable, Equatable {
    public var arp: [String: String]
    public var upnpGateways: [UPnPGateway]
    public var upnpError: String?
    /// Devices announced over Bonjour/mDNS, by IP. nil from helpers older than 0.5.0.
    public var bonjour: [String: BonjourDevice]?
    /// "helper" or "app": who ran the probe.
    public var source: String

    public init(arp: [String: String], upnpGateways: [UPnPGateway], upnpError: String?, source: String) {
        self.arp = arp
        self.upnpGateways = upnpGateways
        self.upnpError = upnpError
        self.source = source
    }

    /// true if the ARP table is empty even though there is a gateway: a sign that macOS
    /// is blocking local network access for whoever ran the probe.
    public var looksBlocked: Bool { arp.isEmpty && NetworkInfo.defaultGateway() != nil }

    public static func run(source: String, inspectUPnP: Bool = true) async -> NetworkProbe {
        let arp = NetworkInfo.arpTable()
        let gateway = NetworkInfo.defaultGateway()
        var probe = NetworkProbe(arp: arp, upnpGateways: [], upnpError: nil, source: source)
        // Bonjour in parallel with UPnP (waits a few seconds for replies).
        let bonjourTask = Task.detached { BonjourScanner.discover(timeout: 4) }
        if arp.isEmpty, gateway != nil {
            probe.upnpError = ScanEngine.localNetworkMessage
            return probe
        }
        if inspectUPnP {
            do {
                probe.upnpGateways = try await UPnPInspector.discover(extraTargets: [gateway].compactMap { $0 })
            } catch {
                probe.upnpError = error.localizedDescription
            }
        }
        probe.bonjour = await bonjourTask.value
        return probe
    }
}
