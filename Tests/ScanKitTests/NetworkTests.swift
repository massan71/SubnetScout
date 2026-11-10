import Foundation
import Testing
@testable import ScanKit

typealias Host = ScanKit.Host

@Suite struct NetworkParsingTests {
    @Test func parsesDHCPDiscoverOutput() {
        let out = """

          Response 1 of 2:
            Interface: en0
            IP Offered: 192.168.1.240
            DHCP Message Type: DHCPOFFER
            Server Identifier: 192.168.1.1
            Router: 192.168.1.1
            Domain Name Server: 192.168.1.1, 1.1.1.1
          Response 2 of 2:
            Interface: en0
            IP Offered: 192.168.1.77
            Server Identifier: 192.168.1.66
            Router: 192.168.1.66
        """
        let offers = DHCPOffer.parse(out)
        #expect(offers.count == 2)
        #expect(offers[0].dnsServers == ["192.168.1.1", "1.1.1.1"])
        #expect(offers[1].server == "192.168.1.66")
        #expect(offers[1].routers == ["192.168.1.66"])
    }

    @Test func parsesIpconfigPacket() {
        let out = """
        op = BOOTREPLY
        yiaddr = 192.168.1.185
        server_identifier (ip): 192.168.1.1
        lease_time (uint32): 0x15180
        router (ip_mult): {192.168.1.1}
        domain_name_server (ip_mult): {192.168.1.1, 9.9.9.9}
        """
        let lease = NetworkInfo.parseDHCPPacket(out)
        #expect(lease.server == "192.168.1.1")
        #expect(lease.routers == ["192.168.1.1"])
        #expect(lease.dnsServers == ["192.168.1.1", "9.9.9.9"])
    }

    @Test func parsesPrescriptOutput() throws {
        let xml = """
        <?xml version="1.0"?><nmaprun version="7.95" args="nmap">
        <prescript><script id="broadcast-dhcp-discover" output="&#xa;  Response 1 of 1:&#xa;    Server Identifier: 192.168.1.1&#xa;"/></prescript>
        <host><status state="up"/><address addr="192.168.1.1" addrtype="ipv4"/><ports/></host>
        </nmaprun>
        """
        let run = try NmapXMLParser.parse(Data(xml.utf8))
        #expect(run.runScripts.map(\.id) == ["broadcast-dhcp-discover"])
        #expect(run.hosts.first?.hostScripts.isEmpty == true)
        #expect(DHCPOffer.parse(run.runScripts[0].output).first?.server == "192.168.1.1")
    }

    @Test func parsesIGDDescriptionAndMapping() {
        let desc = """
        <?xml version="1.0"?><root xmlns="urn:schemas-upnp-org:device-1-0"><device>
        <deviceType>urn:schemas-upnp-org:device:InternetGatewayDevice:1</deviceType>
        <friendlyName>casa</friendlyName><manufacturer>ACME</manufacturer><modelName>Router 9000</modelName>
        <deviceList><device><deviceList><device><serviceList>
          <service><serviceType>urn:schemas-upnp-org:service:WANCommonInterfaceConfig:1</serviceType><controlURL>/ctl/common</controlURL></service>
          <service><serviceType>urn:schemas-upnp-org:service:WANIPConnection:1</serviceType><controlURL>/ctl/IPConn</controlURL></service>
        </serviceList></device></deviceList></device></deviceList></device></root>
        """
        let d = DeviceDescription.parse(desc)
        #expect(d.manufacturer == "ACME")
        #expect(d.modelName == "Router 9000")
        #expect(d.wanService?.controlURL == "/ctl/IPConn")

        let entry = """
        <s:Envelope><s:Body><u:GetGenericPortMappingEntryResponse>
        <NewRemoteHost></NewRemoteHost><NewExternalPort>32400</NewExternalPort><NewProtocol>TCP</NewProtocol>
        <NewInternalPort>32400</NewInternalPort><NewInternalClient>192.168.1.50</NewInternalClient>
        <NewEnabled>1</NewEnabled><NewPortMappingDescription>Plex &amp; co</NewPortMappingDescription>
        <NewLeaseDuration>0</NewLeaseDuration></u:GetGenericPortMappingEntryResponse></s:Body></s:Envelope>
        """
        let m = UPnPInspector.parseMapping(entry)
        #expect(m == UPnPPortMapping(externalPort: 32400, proto: "TCP", internalClient: "192.168.1.50",
                                     internalPort: 32400, enabled: true, description: "Plex & co",
                                     leaseSeconds: 0, remoteHost: ""))
        #expect(UPnPInspector.header("location", in: "HTTP/1.1 200 OK\r\nLOCATION: http://192.168.1.1:5000/desc.xml\r\n") ==
                "http://192.168.1.1:5000/desc.xml")
    }
}

@Suite struct NetworkAuditTests {
    let gw = "192.168.1.1"
    let gwMAC = "AA:00:00:00:00:01"

    func context(_ change: (inout NetworkContext) -> Void = { _ in }) -> NetworkContext {
        var c = NetworkContext(interface: "en0", localIP: "192.168.1.185", gatewayIP: gw, gatewayMAC: gwMAC,
                               dhcpServer: gw, dhcpRouters: [gw], dnsServers: [gw], dhcpProbed: true, upnpProbed: true)
        change(&c)
        return c
    }

    func rules(_ c: NetworkContext, hosts: [Host] = [], previous: ScanResult? = nil) -> [String] {
        NetworkAudit.audit(context: c, hosts: hosts, previous: previous).map(\.ruleID)
    }

    func scan(network: NetworkContext) -> ScanResult {
        ScanResult(target: "192.168.1.0/24", profile: .quick, privileged: false, startedAt: .now, finishedAt: .now,
                   hosts: [], findings: [], network: network)
    }

    @Test func cleanNetworkHasNoFindings() {
        #expect(rules(context(), previous: scan(network: context())).isEmpty)
    }

    @Test func gatewayMACChangeIsDetected() {
        let before = scan(network: context { $0.gatewayMAC = "AA:00:00:00:00:99" })
        #expect(rules(context(), previous: before) == ["gateway-mac-changed"])
    }

    @Test func hostSharingGatewayMACIsDetected() {
        let impostor = Host(ip: "192.168.1.66", mac: gwMAC)
        let f = NetworkAudit.audit(context: context(), hosts: [Host(ip: gw, mac: gwMAC), impostor], previous: nil)
        #expect(f.map(\.ruleID) == ["gateway-mac-shared"])
        #expect(f.first?.severity == .high)
        #expect(f.first?.hostIP == "192.168.1.66")
    }

    @Test func rogueDHCPServerIsDetected() {
        let c = context { $0.dhcpOffers = [DHCPOffer(server: gw, routers: [gw]),
                                          DHCPOffer(server: "192.168.1.66", routers: ["192.168.1.66"], dnsServers: ["192.168.1.66"])] }
        let f = NetworkAudit.audit(context: c, hosts: [], previous: nil)
        #expect(f.map(\.ruleID) == ["dhcp-rogue"])
        #expect(f.first?.detail.contains("192.168.1.66") == true)
    }

    @Test func dnsChecks() {
        #expect(rules(context { $0.dnsServers = ["192.168.1.53"] }) == ["dns-lan-host"])
        #expect(rules(context { $0.dnsServers = ["1.1.1.1"] }).isEmpty)
        #expect(rules(context { $0.dnsServers = ["203.0.113.9"] }) == ["dns-unknown"])
    }

    @Test func upnpWithoutMappingsIsMedium() {
        let c = context { $0.upnpGateways = [UPnPGateway(ip: "192.168.1.17", location: "http://192.168.1.17/d.xml",
                                                         manufacturer: "ACME", model: "Box", mappingsReadable: true)] }
        let f = NetworkAudit.audit(context: c, hosts: [], previous: nil)
        #expect(f.map(\.ruleID) == ["upnp-igd"])
        #expect(f.first?.severity == .medium)
        #expect(f.first?.title.contains("ACME Box") == true)
    }

    @Test func upnpMappingIsHighAndPointsToTheInternalHost() {
        let m = UPnPPortMapping(externalPort: 8080, proto: "TCP", internalClient: "192.168.1.50", internalPort: 80,
                                enabled: true, description: "camera", leaseSeconds: 0, remoteHost: "")
        let c = context { $0.upnpGateways = [UPnPGateway(ip: gw, location: "x", mappings: [m], mappingsReadable: true)] }
        let f = NetworkAudit.audit(context: c, hosts: [Host(ip: "192.168.1.50", hostnames: ["cam.lan"])], previous: nil)
        #expect(f.map(\.ruleID) == ["upnp-port-mapping"])
        #expect(f.first?.severity == .high)
        #expect(f.first?.hostIP == "192.168.1.50")
        #expect(f.first?.port == "80/tcp")
        #expect(f.first?.detail.contains("cam.lan:80") == true)
    }

    @Test func routerManagementServices() {
        let router = Host(ip: gw, ports: [PortInfo(number: 22, proto: "tcp", state: "open", service: ServiceInfo(name: "ssh"))])
        #expect(rules(context(), hosts: [router]) == ["router-management"])
    }
}

@Suite struct NewServiceRuleTests {
    func rules(_ port: PortInfo) -> Set<String> {
        Set(AuditEngine.audit([Host(ip: "192.168.1.9", ports: [port])]).map(\.ruleID))
    }

    @Test func hstsMissingOnHTTPS() {
        let p = PortInfo(number: 443, proto: "tcp", state: "open", service: ServiceInfo(name: "http", tunnel: "ssl"),
                         scripts: [ScriptOutput(id: "http-security-headers",
                                                output: "\n  Strict_Transport_Security: \n    HSTS not configured in HTTPS Server")])
        #expect(rules(p).contains("http-no-hsts"))
    }

    @Test func riskyHTTPMethods() {
        let put = PortInfo(number: 8080, proto: "tcp", state: "open", service: ServiceInfo(name: "http"),
                           scripts: [ScriptOutput(id: "http-methods", output: "\n  Supported Methods: GET PUT DELETE\n  Potentially risky methods: PUT DELETE")])
        let f = AuditEngine.audit([Host(ip: "192.168.1.9", ports: [put])]).first { $0.ruleID == "http-risky-methods" }
        #expect(f?.severity == .medium)
        #expect(AuditEngine.riskyMethods("Potentially risky methods: TRACE") == ["TRACE"])
        #expect(AuditEngine.riskyMethods("Supported Methods: GET HEAD") == nil)
    }

    @Test func weakDHAndHostKeys() {
        let tls = PortInfo(number: 443, proto: "tcp", state: "open", service: ServiceInfo(name: "https"),
                           scripts: [ScriptOutput(id: "ssl-dh-params", output: "\n  VULNERABLE:\n  Diffie-Hellman Key Exchange Insufficient Group Strength")])
        #expect(rules(tls).contains("tls-weak-dh"))
        #expect(AuditEngine.weakHostKeys("\n  1024 aa:bb (DSA)\n  1024 cc:dd (RSA)\n  3072 SHA256:x (RSA)\n  256 ee:ff (ED25519)")
                == ["DSA 1024 bit", "RSA 1024 bit"])
    }
}

/// Optional, against the real network: SUBNETSCOUT_LIVE=1 swift test --filter LiveUPnP
@Suite struct LiveUPnPTests {
    @Test(.enabled(if: ProcessInfo.processInfo.environment["SUBNETSCOUT_LIVE"] == "1"))
    func discoversGatewaysOnThisNetwork() async {
        let raw = UPnPInspector.ssdpSearch(extraTargets: [], timeout: 3)
        print("SSDP:", raw.responses, "send error:", raw.sendError ?? "-")
        let gws = (try? await UPnPInspector.discover(extraTargets: [NetworkInfo.defaultGateway()].compactMap { $0 })) ?? []
        for gw in gws {
            print("UPnP:", gw.displayName, gw.ip, "service:", gw.serviceType ?? "-",
                  "readable:", gw.mappingsReadable, "ports:", gw.mappings.count)
        }
        #expect(!gws.isEmpty)
    }

    @Test(.enabled(if: ProcessInfo.processInfo.environment["SUBNETSCOUT_LIVE"] == "1" && NmapLocator.find() != nil))
    func discoveryScanCollectsNetworkContext() async throws {
        let cidr = try #require(NetworkInfo.interfaces().first?.cidr)
        let result = try await ScanEngine(nmapPath: NmapLocator.find()!).scan(targets: [cidr], profile: .discovery, privileged: false)
        let net = try #require(result.network)
        print("NETWORK: gateway", net.gatewayIP ?? "-", net.gatewayMAC ?? "-", "dhcp", net.dhcpServer ?? "-", "dns", net.dnsServers,
              "upnp", net.upnpGateways.map(\.displayName), net.upnpError ?? "")
        for f in result.findings { print("FINDING:", f.severity.label, f.ruleID, f.hostIP, f.title) }
        #expect(net.gatewayIP != nil)
    }
}


/// The root script of password mode must stop nmap on cancellation or if the app dies.
@Suite struct PrivilegedScriptTests {
    func fakeNmap() throws -> (URL, URL) {
        let dir = FileManager.default.temporaryDirectory.appending(path: "ss-script-\(UUID().uuidString)")
        try FileManager.default.createDirectory(at: dir, withIntermediateDirectories: true)
        let fake = dir.appending(path: "nmap")
        try "#!/bin/sh\nexec sleep 30\n".write(to: fake, atomically: true, encoding: .utf8)
        try FileManager.default.setAttributes([.posixPermissions: 0o755], ofItemAtPath: fake.path)
        return (dir, fake)
    }

    func run(_ script: String) throws -> (Process, Date) {
        let p = Process()
        p.executableURL = URL(fileURLWithPath: "/bin/sh")
        p.arguments = ["-c", script]
        try p.run()
        return (p, Date())
    }

    @Test func cancelFileStopsNmap() throws {
        let (dir, fake) = try fakeNmap()
        defer { try? FileManager.default.removeItem(at: dir) }
        let cancel = dir.appending(path: "x.cancel")
        let script = NmapRunner.privilegedScript(nmapPath: fake.path, arguments: [], targets: ["127.0.0.1"],
                                                 xml: dir.appending(path: "x.xml").path, err: dir.appending(path: "x.err").path,
                                                 cancel: cancel.path, appPID: getpid())
        let (p, start) = try run(script)
        Thread.sleep(forTimeInterval: 1)
        FileManager.default.createFile(atPath: cancel.path, contents: nil)
        p.waitUntilExit()
        #expect(Date().timeIntervalSince(start) < 5)
        #expect(p.terminationStatus == 0)
    }

    @Test func deadAppStopsNmap() throws {
        let (dir, fake) = try fakeNmap()
        defer { try? FileManager.default.removeItem(at: dir) }
        // PID of an already terminated process = "dead app".
        let gone = Process()
        gone.executableURL = URL(fileURLWithPath: "/usr/bin/true")
        try gone.run(); gone.waitUntilExit()
        let script = NmapRunner.privilegedScript(nmapPath: fake.path, arguments: [], targets: ["127.0.0.1"],
                                                 xml: dir.appending(path: "x.xml").path, err: dir.appending(path: "x.err").path,
                                                 cancel: dir.appending(path: "x.cancel").path, appPID: gone.processIdentifier)
        let (p, start) = try run(script)
        p.waitUntilExit()
        #expect(Date().timeIntervalSince(start) < 5)
    }

    @Test func scriptQuotesHostileArguments() {
        let s = NmapRunner.privilegedScript(nmapPath: "/x/nmap", arguments: ["--script", "a'b"], targets: ["10.0.0.1"],
                                            xml: "/t/x.xml", err: "/t/x.err", cancel: "/t/x.cancel", appPID: 42)
        #expect(s.contains("'a'\\''b'"))
        #expect(s.hasPrefix("'/x/nmap' "))
    }
}

@Suite struct PrivateTargetTests {
    @Test func acceptsPrivateForms() throws {
        let ok = ["10.0.1.0/24", "192.168.1.1-50", "172.16.0-3.*", "192.168.0.1,5,9", "169.254.1.1",
                  "100.64.0.0/16", "127.0.0.1", "fe80::1", "fd12:3456::/64", "::1", "localhost"]
        let out = try PrivateTargets.validate(ok)
        #expect(out.contains("10.0.1.0/24"))
        #expect(!out.contains("localhost"), "hostnames are replaced by the resolved IPs")
        #expect(out.contains("127.0.0.1") || out.contains("::1"))
    }

    @Test func rejectsPublicOrBroadTargets() {
        for t in ["8.8.8.8", "10.0.0.0/7", "192.168.0.0/15", "172.15.255.255", "172.16-32.0.1", "1.1.1.*",
                  "2001:4860::8888", "fe80::/9", "0.0.0.0/0"] {
            #expect(throws: PrivateTargets.Rejection.self, "\(t) must be rejected") { try PrivateTargets.validate([t]) }
        }
    }

    @Test func spanOfNmapRanges() {
        #expect(PrivateTargets.ipv4Span("10.0.1.1-50")! == (0x0A00_0101, 0x0A00_0132))
        #expect(PrivateTargets.ipv4Span("10.0.0-3.*")! == (0x0A00_0000, 0x0A00_03FF))
        #expect(PrivateTargets.ipv4Span("nas.local") == nil)
    }
}
