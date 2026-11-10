import Foundation

/// Regole a livello di rete: attacchi in corso sulla LAN (ARP spoofing, DHCP
/// non autorizzati), DNS anomali ed esposizione verso Internet (UPnP).
public enum NetworkAudit {
    public static func audit(context: NetworkContext, hosts: [Host], previous: ScanResult?) -> [Finding] {
        var f: [Finding] = []
        let gatewayIP = context.gatewayIP

        // --- ARP spoofing: il MAC del gateway è cambiato rispetto alla scansione precedente
        if let gw = gatewayIP, let mac = context.gatewayMAC,
           let prev = previous?.network, prev.gatewayIP == gw, let oldMAC = prev.gatewayMAC, oldMAC != mac {
            f.append(Finding(
                ruleID: "gateway-mac-changed", severity: .high,
                title: "The gateway MAC address has changed",
                detail: "\(gw) used to answer with \(oldMAC), now with \(mac). If you have not replaced the router, someone may be intercepting traffic (ARP spoofing).",
                remediation: "Check the MAC on the router label or admin page. If it does not match, disconnect unknown devices and check the ARP table.",
                hostIP: gw, evidence: "\(oldMAC) → \(mac)"))
        }

        // --- ARP spoofing: un altro IP usa lo stesso MAC del gateway
        if let gw = gatewayIP, let mac = context.gatewayMAC {
            let impostors = hosts.filter { $0.ip != gw && $0.mac == mac }
            for h in impostors {
                f.append(Finding(
                    ruleID: "gateway-mac-shared", severity: .high,
                    title: "A device uses the same MAC as the gateway",
                    detail: "\(h.ip) and the gateway \(gw) both answer with \(mac). This is the typical sign of an ARP spoofing attack, or of a router with several addresses on the same network.",
                    remediation: "Identify device \(h.ip). If it is not the router itself, disconnect it from the network.",
                    hostIP: h.ip, evidence: mac))
            }
        }

        // --- DHCP: offerte da server diversi da quello che ci ha assegnato l'indirizzo
        let expected = Set([context.dhcpServer, gatewayIP].compactMap { $0 })
        var reported = Set<String>()
        for offer in context.dhcpOffers where !expected.contains(offer.server) && reported.insert(offer.server).inserted {
            let gwInfo = offer.routers.isEmpty ? "" : " It offers \(offer.routers.joined(separator: ", ")) as gateway"
            let dnsInfo = offer.dnsServers.isEmpty ? "" : " and \(offer.dnsServers.joined(separator: ", ")) as DNS."
            f.append(Finding(
                ruleID: "dhcp-rogue", severity: .high,
                title: "Rogue DHCP server",
                detail: "\(offer.server) answers DHCP requests, but this Mac got its address from \(expected.sorted().joined(separator: "/")).\(gwInfo)\(dnsInfo) A rogue DHCP server can hijack the gateway and DNS of your devices.",
                remediation: "Find device \(offer.server) (often a second router or a hotspot) and turn off its DHCP server.",
                hostIP: offer.server))
        }
        // Il server atteso offre gateway o DNS diversi da quelli ricevuti
        for offer in context.dhcpOffers where expected.contains(offer.server) {
            let oddRouters = Set(offer.routers).subtracting(context.dhcpRouters)
            if !context.dhcpRouters.isEmpty, !oddRouters.isEmpty {
                f.append(Finding(
                    ruleID: "dhcp-router-mismatch", severity: .medium,
                    title: "DHCP offers a different gateway",
                    detail: "\(offer.server) now offers \(oddRouters.sorted().joined(separator: ", ")) as gateway instead of \(context.dhcpRouters.joined(separator: ", ")).",
                    remediation: "Check the DHCP configuration of the router.",
                    hostIP: offer.server))
            }
        }

        // --- DNS assegnati
        let localNet = context.localIP.flatMap(IPv4.parse)
        for dns in context.dnsServers {
            guard let v = IPv4.parse(dns), dns != gatewayIP else { continue }
            if let local = localNet, v >> 8 == local >> 8 || IPv4.isPrivate(v) {
                f.append(Finding(
                    ruleID: "dns-lan-host", severity: .low,
                    title: "DNS provided by another device on the LAN",
                    detail: "DHCP hands out \(dns) as DNS, which is not the gateway. This is normal with Pi-hole or AdGuard; otherwise that device sees (and can forge) every lookup.",
                    remediation: "If you do not use a local DNS, set the router or ISP DNS in the router.",
                    hostIP: dns))
            } else if !IPv4.isWellKnownResolver(dns) {
                f.append(Finding(
                    ruleID: "dns-unknown", severity: .low,
                    title: "Unrecognized external DNS",
                    detail: "DHCP hands out \(dns) as DNS: it is neither a well-known public resolver nor a LAN address.",
                    remediation: "Check that it is your ISP DNS; if in doubt, use the router DNS or a well-known resolver.",
                    hostIP: gatewayIP ?? dns))
            }
        }

        // --- UPnP: router che permettono ai dispositivi di aprire porte verso Internet
        for gw in context.upnpGateways {
            let active = gw.mappings.filter(\.enabled)
            if active.isEmpty {
                f.append(Finding(
                    ruleID: "upnp-igd", severity: .medium,
                    title: "UPnP enabled on router \(gw.displayName)",
                    detail: gw.mappingsReadable
                        ? "No ports are open right now, but any device on the LAN (even a compromised one) can open them to the Internet without asking."
                        : "The router accepts UPnP requests: devices on the LAN can open ports to the Internet without asking.",
                    remediation: "Turn off UPnP on the router and open only the ports you need manually.",
                    hostIP: gw.ip))
            }
            for m in active {
                let who = hosts.first { $0.ip == m.internalClient }?.displayName ?? m.internalClient
                let label = m.description.isEmpty ? "" : " (“\(m.description)”)"
                let anyone = m.remoteHost.isEmpty || m.remoteHost == "0.0.0.0"
                f.append(Finding(
                    ruleID: "upnp-port-mapping", severity: anyone ? .high : .medium,
                    title: "\(m.proto) port \(m.externalPort) exposed to the Internet",
                    detail: "\(gw.displayName) forwards port \(m.externalPort)/\(m.proto.lowercased()) to \(who):\(m.internalPort)\(label)"
                        + (anyone ? ", reachable by anyone." : ", only from \(m.remoteHost).")
                        + (m.leaseSeconds == 0 ? " The rule is permanent." : ""),
                    remediation: "If it is not needed, remove the rule from the router and turn off UPnP. If it is, make sure \(who) is up to date.",
                    hostIP: m.internalClient, port: "\(m.internalPort)/\(m.proto.lowercased())",
                    evidence: "\(gw.ip):\(m.externalPort) → \(m.internalClient):\(m.internalPort)"))
            }
        }

        // --- Gestione del router raggiungibile dalla LAN
        let routerIPs = Set([gatewayIP].compactMap { $0 } + context.upnpGateways.map(\.ip))
        for h in hosts where routerIPs.contains(h.ip) {
            let mgmt = h.openPorts.filter {
                ["ssh", "telnet", "snmp"].contains($0.serviceName) || [22, 23, 161, 8291].contains($0.number)
            }
            if !mgmt.isEmpty {
                f.append(Finding(
                    ruleID: "router-management", severity: .low,
                    title: "Router remote management reachable",
                    detail: "Router \(h.displayName) exposes management services to the LAN: \(mgmt.map { "\($0.serviceName.isEmpty ? "?" : $0.serviceName) (\($0.id))" }.joined(separator: ", ")).",
                    remediation: "Restrict the router SSH/Telnet/SNMP to a single PC or a management network, or turn them off.",
                    hostIP: h.ip))
            }
        }
        return f
    }
}

extension IPv4 {
    static func isPrivate(_ v: UInt32) -> Bool {
        v >> 24 == 10 || v >> 20 == 0xAC1 || v >> 16 == 0xC0A8 || v >> 16 == 0xA9FE || v >> 22 == 0x191 // 100.64/10
    }

    static func isWellKnownResolver(_ ip: String) -> Bool {
        ["1.1.1.1", "1.0.0.1", "8.8.8.8", "8.8.4.4", "9.9.9.9", "149.112.112.112",
         "208.67.222.222", "208.67.220.220", "94.140.14.14", "94.140.15.15"].contains(ip)
    }
}
