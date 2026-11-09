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
    public func scan(targets: [String], profile: ScanProfile, privileged: Bool, previous: ScanResult? = nil,
                     onProgress: @escaping @Sendable (Double) -> Void = { _ in }) async throws -> ScanResult {
        try await scan(targets: targets, profile: profile,
                       executor: LocalNmapExecutor(nmapPath: nmapPath, askPassword: privileged),
                       previous: previous, onProgress: onProgress)
    }

    /// Scansione con un esecutore qualsiasi (es. il privileged helper).
    /// - Parameter previous: scansione precedente dello stesso target, per le regole che
    ///   confrontano lo stato della rete (es. MAC del gateway cambiato).
    public func scan(targets: [String], profile: ScanProfile, executor: any NmapExecutor,
                     previous: ScanResult? = nil, inspectUPnP: Bool = true,
                     onProgress: @escaping @Sendable (Double) -> Void = { _ in }) async throws -> ScanResult {
        let started = Date()
        let xml = try await executor.execute(profile: profile, targets: targets, onProgress: onProgress)
        let run = try NmapXMLParser.parse(xml)
        let hosts = enrich(run.hosts)
        var context = networkContext(hosts: hosts, runScripts: run.runScripts)
        if inspectUPnP {
            do {
                context.upnpGateways = try await UPnPInspector.discover(extraTargets: [context.gatewayIP].compactMap { $0 })
                context.upnpProbed = true
            } catch {
                context.upnpError = error.localizedDescription
            }
        }
        return ScanResult(
            target: targets.joined(separator: " "),
            profile: profile,
            privileged: executor.isPrivileged,
            startedAt: run.startedAt ?? started,
            finishedAt: run.finishedAt ?? Date(),
            nmapVersion: run.version,
            nmapArgs: run.args,
            hosts: hosts,
            findings: Self.sorted(AuditEngine.audit(hosts)
                                  + NetworkAudit.audit(context: context, hosts: hosts, previous: previous)),
            network: context
        )
    }

    /// Gateway, lease DHCP e offerte DHCP (se è stato eseguito broadcast-dhcp-discover).
    func networkContext(hosts: [Host], runScripts: [ScriptOutput]) -> NetworkContext {
        let route = NetworkInfo.defaultRoute()
        let iface = route.interface.flatMap { name in NetworkInfo.interfaces().first { $0.name == name } }
        let lease = route.interface.flatMap(NetworkInfo.dhcpLease(interface:))
        let gatewayMAC = hosts.first { $0.ip == route.gateway }?.mac
            ?? route.gateway.flatMap { NetworkInfo.arpTable()[$0] }
        let dhcpScript = runScripts.first { $0.id == "broadcast-dhcp-discover" }
        return NetworkContext(interface: route.interface, localIP: iface?.ip, gatewayIP: route.gateway,
                              gatewayMAC: gatewayMAC, dhcpServer: lease?.server,
                              dhcpRouters: lease?.routers ?? [], dnsServers: lease?.dnsServers ?? [],
                              dhcpOffers: dhcpScript.map { DHCPOffer.parse($0.output) } ?? [],
                              dhcpProbed: dhcpScript != nil)
    }

    static func sorted(_ findings: [Finding]) -> [Finding] {
        var seen = Set<String>()
        return findings.filter { seen.insert($0.id).inserted }.sorted {
            ($0.severity, $1.hostIP, $1.port ?? "") > ($1.severity, $0.hostIP, $0.port ?? "")
        }
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
