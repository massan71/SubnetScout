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
                title: "Il MAC del gateway è cambiato",
                detail: "\(gw) rispondeva con \(oldMAC), ora con \(mac). Se non hai sostituito il router, qualcuno potrebbe intercettare il traffico (ARP spoofing).",
                remediation: "Verifica il MAC sull'etichetta o nel pannello del router. Se non torna, scollega i dispositivi sconosciuti e controlla la tabella ARP.",
                hostIP: gw, evidence: "\(oldMAC) → \(mac)"))
        }

        // --- ARP spoofing: un altro IP usa lo stesso MAC del gateway
        if let gw = gatewayIP, let mac = context.gatewayMAC {
            let impostors = hosts.filter { $0.ip != gw && $0.mac == mac }
            for h in impostors {
                f.append(Finding(
                    ruleID: "gateway-mac-shared", severity: .high,
                    title: "Un dispositivo usa lo stesso MAC del gateway",
                    detail: "\(h.ip) e il gateway \(gw) rispondono entrambi con \(mac). È il segno tipico di un attacco ARP spoofing, oppure di un router con più indirizzi sulla stessa rete.",
                    remediation: "Identifica il dispositivo \(h.ip). Se non è il router stesso, scollegalo dalla rete.",
                    hostIP: h.ip, evidence: mac))
            }
        }

        // --- DHCP: offerte da server diversi da quello che ci ha assegnato l'indirizzo
        let expected = Set([context.dhcpServer, gatewayIP].compactMap { $0 })
        var reported = Set<String>()
        for offer in context.dhcpOffers where !expected.contains(offer.server) && reported.insert(offer.server).inserted {
            let gwInfo = offer.routers.isEmpty ? "" : " Propone come gateway \(offer.routers.joined(separator: ", "))"
            let dnsInfo = offer.dnsServers.isEmpty ? "" : " e come DNS \(offer.dnsServers.joined(separator: ", "))."
            f.append(Finding(
                ruleID: "dhcp-rogue", severity: .high,
                title: "Server DHCP non autorizzato",
                detail: "\(offer.server) risponde alle richieste DHCP, ma l'indirizzo di questo Mac viene da \(expected.sorted().joined(separator: "/")).\(gwInfo)\(dnsInfo) Un DHCP estraneo può dirottare gateway e DNS dei dispositivi.",
                remediation: "Individua il dispositivo \(offer.server) (spesso un secondo router o un hotspot) e disattivane il DHCP.",
                hostIP: offer.server))
        }
        // Il server atteso offre gateway o DNS diversi da quelli ricevuti
        for offer in context.dhcpOffers where expected.contains(offer.server) {
            let oddRouters = Set(offer.routers).subtracting(context.dhcpRouters)
            if !context.dhcpRouters.isEmpty, !oddRouters.isEmpty {
                f.append(Finding(
                    ruleID: "dhcp-router-mismatch", severity: .medium,
                    title: "Il DHCP offre un gateway diverso",
                    detail: "\(offer.server) ora propone \(oddRouters.sorted().joined(separator: ", ")) come gateway invece di \(context.dhcpRouters.joined(separator: ", ")).",
                    remediation: "Controlla la configurazione DHCP del router.",
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
                    title: "DNS fornito da un altro dispositivo della LAN",
                    detail: "Il DHCP indica \(dns) come DNS, che non è il gateway. È normale con Pi-hole o AdGuard; altrimenti quel dispositivo vede (e può falsificare) tutte le risoluzioni.",
                    remediation: "Se non usi un DNS locale, imposta nel router il DNS del router o del provider.",
                    hostIP: dns))
            } else if !IPv4.isWellKnownResolver(dns) {
                f.append(Finding(
                    ruleID: "dns-unknown", severity: .low,
                    title: "DNS esterno non riconosciuto",
                    detail: "Il DHCP indica \(dns) come DNS: non è un resolver pubblico noto né un indirizzo della LAN.",
                    remediation: "Verifica che sia il DNS del tuo provider; in caso di dubbio usa il DNS del router o un resolver noto.",
                    hostIP: gatewayIP ?? dns))
            }
        }

        // --- UPnP: router che permettono ai dispositivi di aprire porte verso Internet
        for gw in context.upnpGateways {
            let active = gw.mappings.filter(\.enabled)
            if active.isEmpty {
                f.append(Finding(
                    ruleID: "upnp-igd", severity: .medium,
                    title: "UPnP attivo sul router \(gw.displayName)",
                    detail: gw.mappingsReadable
                        ? "Nessuna porta è aperta ora, ma qualsiasi dispositivo della LAN (anche uno compromesso) può aprirne verso Internet senza chiedere."
                        : "Il router accetta richieste UPnP: i dispositivi della LAN possono aprire porte verso Internet senza chiedere.",
                    remediation: "Disattiva UPnP nel router e apri a mano solo le porte necessarie.",
                    hostIP: gw.ip))
            }
            for m in active {
                let who = hosts.first { $0.ip == m.internalClient }?.displayName ?? m.internalClient
                let label = m.description.isEmpty ? "" : " («\(m.description)»)"
                let anyone = m.remoteHost.isEmpty || m.remoteHost == "0.0.0.0"
                f.append(Finding(
                    ruleID: "upnp-port-mapping", severity: anyone ? .high : .medium,
                    title: "Porta \(m.proto) \(m.externalPort) esposta su Internet",
                    detail: "\(gw.displayName) inoltra la porta \(m.externalPort)/\(m.proto.lowercased()) a \(who):\(m.internalPort)\(label)"
                        + (anyone ? ", raggiungibile da chiunque." : ", solo da \(m.remoteHost).")
                        + (m.leaseSeconds == 0 ? " La regola è permanente." : ""),
                    remediation: "Se non serve, rimuovi la regola dal router e disattiva UPnP. Se serve, verifica che \(who) sia aggiornato.",
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
                    title: "Gestione remota del router accessibile",
                    detail: "Il router \(h.displayName) espone servizi di amministrazione alla LAN: \(mgmt.map { "\($0.serviceName.isEmpty ? "?" : $0.serviceName) (\($0.id))" }.joined(separator: ", ")).",
                    remediation: "Limita SSH/Telnet/SNMP del router a un solo PC o a una rete di gestione, oppure disattivali.",
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
