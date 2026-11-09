import Foundation

/// Orchestrazione completa: nmap → parsing → arricchimento (MAC, produttore, gateway) → audit.
public struct ScanEngine: Sendable {
    public let nmapPath: String
    private let vendors: MACVendorDB

    public init(nmapPath: String) {
        self.nmapPath = nmapPath
        self.vendors = MACVendorDB(nmapPath: nmapPath)
    }

    /// Scansione con nmap locale (utente normale o con richiesta password).
    public func scan(targets: [String], profile: ScanProfile, privileged: Bool,
                     onProgress: @escaping @Sendable (Double) -> Void = { _ in }) async throws -> ScanResult {
        try await scan(targets: targets, profile: profile,
                       executor: LocalNmapExecutor(nmapPath: nmapPath, askPassword: privileged),
                       onProgress: onProgress)
    }

    /// Scansione con un esecutore qualsiasi (es. il privileged helper).
    public func scan(targets: [String], profile: ScanProfile, executor: any NmapExecutor,
                     onProgress: @escaping @Sendable (Double) -> Void = { _ in }) async throws -> ScanResult {
        let started = Date()
        let xml = try await executor.execute(profile: profile, targets: targets, onProgress: onProgress)
        let run = try NmapXMLParser.parse(xml)
        let hosts = enrich(run.hosts)
        return ScanResult(
            target: targets.joined(separator: " "),
            profile: profile,
            privileged: executor.isPrivileged,
            startedAt: run.startedAt ?? started,
            finishedAt: run.finishedAt ?? Date(),
            nmapVersion: run.version,
            nmapArgs: run.args,
            hosts: hosts,
            findings: AuditEngine.audit(hosts)
        )
    }

    public func enrich(_ hosts: [Host]) -> [Host] {
        let arp = NetworkInfo.arpTable()
        let gateway = NetworkInfo.defaultGateway()
        let localIPs = Set(NetworkInfo.interfaces().map(\.ip))
        return hosts.map { h in
            var h = h
            if h.mac == nil { h.mac = arp[h.ip] }
            if h.vendor == nil || h.vendor?.isEmpty == true, let mac = h.mac { h.vendor = vendors.vendor(for: mac) }
            h.isGateway = h.ip == gateway
            h.isLocalMachine = localIPs.contains(h.ip)
            if h.isLocalMachine, h.hostnames.isEmpty, let name = Host.localName { h.hostnames = [name] }
            return h
        }
        .sorted { $0.ipSortKey < $1.ipSortKey }
    }
}

extension Host {
    static var localName: String? {
        ProcessInfo.processInfo.hostName.isEmpty ? nil : ProcessInfo.processInfo.hostName
    }
}
