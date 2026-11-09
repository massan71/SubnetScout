import Foundation

/// Differenze tra due scansioni dello stesso target.
public struct ScanDiff: Hashable, Sendable {
    public struct PortChange: Hashable, Sendable {
        public var hostIP: String
        public var hostName: String
        public var port: String
        public var service: String
    }

    public var previousScanDate: Date
    public var newHosts: [Host]
    public var goneHosts: [Host]
    public var openedPorts: [PortChange]
    public var closedPorts: [PortChange]
    public var newFindings: [Finding]

    public var isEmpty: Bool {
        newHosts.isEmpty && goneHosts.isEmpty && openedPorts.isEmpty && closedPorts.isEmpty && newFindings.isEmpty
    }

    public init(previous: ScanResult, current: ScanResult) {
        previousScanDate = previous.finishedAt
        // I dispositivi si riconoscono per MAC quando disponibile (l'IP DHCP può cambiare).
        let prevKeys = Set(previous.hosts.map(\.deviceKey) + previous.hosts.map(\.ip))
        let currKeys = Set(current.hosts.map(\.deviceKey) + current.hosts.map(\.ip))
        newHosts = current.hosts.filter { !prevKeys.contains($0.deviceKey) && !prevKeys.contains($0.ip) }
        goneHosts = previous.hosts.filter { !currKeys.contains($0.deviceKey) && !currKeys.contains($0.ip) }

        var opened: [PortChange] = []
        var closed: [PortChange] = []
        if previous.profile.scansPorts && current.profile.scansPorts {
            let prevByKey = Dictionary(previous.hosts.map { ($0.deviceKey, $0) }, uniquingKeysWith: { a, _ in a })
            for host in current.hosts {
                guard let old = prevByKey[host.deviceKey] else { continue }
                let before = Dictionary(old.openPorts.map { ($0.id, $0) }, uniquingKeysWith: { a, _ in a })
                let now = Dictionary(host.openPorts.map { ($0.id, $0) }, uniquingKeysWith: { a, _ in a })
                for (id, p) in now where before[id] == nil {
                    opened.append(PortChange(hostIP: host.ip, hostName: host.displayName, port: id, service: p.serviceName))
                }
                // Una porta "sparita" conta solo se la nuova scansione l'ha effettivamente controllata.
                if current.profile == previous.profile || current.profile == .full {
                    for (id, p) in before where now[id] == nil {
                        closed.append(PortChange(hostIP: host.ip, hostName: host.displayName, port: id, service: p.serviceName))
                    }
                }
            }
        }
        openedPorts = opened.sorted { ($0.hostIP, $0.port) < ($1.hostIP, $1.port) }
        closedPorts = closed.sorted { ($0.hostIP, $0.port) < ($1.hostIP, $1.port) }

        let oldFindingIDs = Set(previous.findings.map(\.id))
        newFindings = current.findings.filter { !oldFindingIDs.contains($0.id) }
    }
}
