import Foundation

/// Full orchestration: nmap → parsing → enrichment (MAC, vendor, gateway) → audit.
public struct ScanEngine: Sendable {
    public let nmapPath: String
    private let vendors: MACVendorDB

    public init(nmapPath: String) {
        self.nmapPath = nmapPath
        self.vendors = MACVendorDB(nmapPath: nmapPath)
    }

    /// Scan with local nmap (normal user or with a password prompt).
    public func scan(targets: [String], profile: ScanProfile, privileged: Bool, previous: ScanResult? = nil,
                     onProgress: @escaping @Sendable (Double) -> Void = { _ in }) async throws -> ScanResult {
        try await scan(targets: targets, profile: profile,
                       executor: LocalNmapExecutor(nmapPath: nmapPath, askPassword: privileged),
                       previous: previous, onProgress: onProgress)
    }

    /// Provides the ARP table and UPnP routers (from the app or from the helper).
    public typealias ProbeProvider = @Sendable () async -> NetworkProbe

    /// Scan with any executor (e.g. the privileged helper).
    /// - Parameters:
    ///   - previous: previous scan of the same target, for the rules that
    ///     compare the network state (e.g. gateway MAC changed).
    ///   - probe: who reads ARP and UPnP; by default the app itself (subject to the
    ///     Local Network permission). With the helper active the app passes the helper's probe.
    public func scan(targets: [String], profile: ScanProfile, executor: any NmapExecutor,
                     previous: ScanResult? = nil, inspectUPnP: Bool = true, probe: ProbeProvider? = nil,
                     cveLookup: NVDClient? = nil,
                     onStatus: @escaping @Sendable (String) -> Void = { _ in },
                     onProgress: @escaping @Sendable (Double) -> Void = { _ in }) async throws -> ScanResult {
        let started = Date()
        let xml = try await executor.execute(profile: profile, targets: targets, onProgress: onProgress)
        let run = try NmapXMLParser.parse(xml)
        let probe = await (probe ?? { await NetworkProbe.run(source: "app", inspectUPnP: inspectUPnP) })()
        let hosts = enrich(run.hosts, arp: probe.arp, bonjour: probe.bonjour ?? [:])
        var context = networkContext(hosts: hosts, runScripts: run.runScripts, nmapArgs: run.args ?? "", arp: probe.arp)
        context.upnpGateways = probe.upnpGateways
        context.upnpError = probe.upnpError
        context.upnpProbed = inspectUPnP && probe.upnpError == nil

        // Known vulnerabilities: only product and version go to NVD.
        var vulnerabilities: [String: [CVEEntry]]?
        var cveError: String?
        let queries = CVEAudit.queries(for: hosts)
        if let cveLookup, profile.scansPorts, !queries.isEmpty {
            do {
                vulnerabilities = try await cveLookup.lookup(queries) { i, n in onStatus("Looking up CVEs \(i) of \(n)") }
            } catch is CancellationError {
                throw CancellationError()
            } catch {
                cveError = error.localizedDescription
            }
        }
        let cveFindings = vulnerabilities.map { CVEAudit.findings(hosts: hosts, vulnerabilities: $0) } ?? []

        var result = ScanResult(
            target: targets.joined(separator: " "),
            profile: profile,
            privileged: executor.isPrivileged,
            startedAt: run.startedAt ?? started,
            finishedAt: run.finishedAt ?? Date(),
            nmapVersion: run.version,
            nmapArgs: run.args,
            hosts: hosts,
            findings: Self.sorted(AuditEngine.audit(hosts)
                                  + NetworkAudit.audit(context: context, hosts: hosts, previous: previous)
                                  + cveFindings),
            network: context
        )
        result.vulnerabilities = vulnerabilities
        result.cveError = cveError
        return result
    }

    public static let localNetworkMessage =
        "macOS is blocking local network access for SubnetScout: allow it in System Settings › Privacy & Security › Local Network, or install the helper (it is not subject to this permission)."

    /// Gateway, DHCP lease and DHCP offers (if broadcast-dhcp-discover ran).
    func networkContext(hosts: [Host], runScripts: [ScriptOutput], nmapArgs: String, arp: [String: String]) -> NetworkContext {
        let route = NetworkInfo.defaultRoute()
        let iface = route.interface.flatMap { name in NetworkInfo.interfaces().first { $0.name == name } }
        let lease = route.interface.flatMap(NetworkInfo.dhcpLease(interface:))
        let gatewayMAC = hosts.first { $0.ip == route.gateway }?.mac
            ?? route.gateway.flatMap { arp[$0] }
        let dhcpScript = runScripts.first { $0.id == "broadcast-dhcp-discover" }
        var context = NetworkContext(interface: route.interface, localIP: iface?.ip, gatewayIP: route.gateway,
                                     gatewayMAC: gatewayMAC, dhcpServer: lease?.server,
                                     dhcpRouters: lease?.routers ?? [], dnsServers: lease?.dnsServers ?? [],
                                     dhcpOffers: dhcpScript.map { DHCPOffer.parse($0.output) } ?? [],
                                     // With no replies the script produces no output: what matters is that it ran.
                                     dhcpProbed: dhcpScript != nil || nmapArgs.contains("broadcast-dhcp-discover"))
        // On an active LAN the ARP table contains at least the gateway: if it is empty,
        // macOS is denying the Local Network permission to whoever ran the probe.
        context.localNetworkBlocked = route.gateway != nil && iface != nil && arp.isEmpty
        return context
    }

    static func sorted(_ findings: [Finding]) -> [Finding] {
        var seen = Set<String>()
        return findings.filter { seen.insert($0.id).inserted }.sorted {
            ($0.severity, $1.hostIP, $1.port ?? "") > ($1.severity, $0.hostIP, $0.port ?? "")
        }
    }

    public func enrich(_ hosts: [Host], arp: [String: String]? = nil, bonjour: [String: BonjourDevice] = [:]) -> [Host] {
        let arp = arp ?? NetworkInfo.arpTable()
        let gateway = NetworkInfo.defaultGateway()
        let localIPs = Set(NetworkInfo.interfaces().map(\.ip))
        return hosts.map { h in
            var h = h
            // This Mac announces itself on 127.0.0.1: match it to its real address.
            if let b = bonjour[h.ip] ?? (localIPs.contains(h.ip) ? bonjour["127.0.0.1"] : nil) {
                h.bonjourName = b.bestName
                h.model = b.model
                h.bonjourServices = b.services
            }
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
