import Foundation
import ScanKit

/// Diagnostica da riga di comando:
///
///     /Applications/SubnetScout.app/Contents/MacOS/SubnetScout --diagnose-network
///
/// Utile perché permesso «Rete locale» e App Transport Security valgono per l'app,
/// non per i test o per gli script lanciati dal terminale.
enum Diagnostics {
    static func runAndExit() -> Never {
        let done = DispatchSemaphore(value: 0)
        Task.detached {
            await run()
            done.signal()
        }
        done.wait()
        exit(0)
    }

    static func run() async {
        func line(_ label: String, _ value: String) { print(label.padding(toLength: 22, withPad: " ", startingAt: 0), value) }

        let route = NetworkInfo.defaultRoute()
        line("Gateway / interfaccia", "\(route.gateway ?? "—") / \(route.interface ?? "—")")
        let arp = NetworkInfo.arpTable()
        line("Tabella ARP", "\(arp.count) voci" + (arp.isEmpty ? "  ⚠︎ vuota: permesso «Rete locale» negato?" : ""))
        if let gw = route.gateway { line("MAC del gateway", arp[gw] ?? "—") }
        if let iface = route.interface, let lease = NetworkInfo.dhcpLease(interface: iface) {
            line("Lease DHCP", "server \(lease.server ?? "—"), router \(lease.routers.joined(separator: ",")), DNS \(lease.dnsServers.joined(separator: ","))")
        }

        if HelperClient.isBundled, HelperClient.service.status == .enabled {
            do {
                let p = try await HelperClient.networkProbe()
                line("Sonda del helper", "\(p.arp.count) voci ARP, router UPnP: \(p.upnpGateways.map { "\($0.displayName) (\($0.ip), \($0.mappings.count) porte)" }.joined(separator: "; ").isEmpty ? "nessuno" : p.upnpGateways.map { "\($0.displayName) (\($0.ip), \($0.mappings.count) porte)" }.joined(separator: "; "))" + (p.upnpError.map { " · \($0)" } ?? ""))
                for (ip, d) in (p.bonjour ?? [:]).sorted(by: { (IPv4.parse($0.key) ?? 0) < (IPv4.parse($1.key) ?? 0) }) {
                    line("  Bonjour \(ip)", "\(d.bestName ?? "—") · \(d.model ?? "—") · \(d.services.prefix(3).joined(separator: ", "))")
                }
            } catch {
                line("Sonda del helper", "ERRORE: \(error.localizedDescription)")
            }
        } else {
            line("Sonda del helper", "helper non attivo")
        }

        let search = UPnPInspector.ssdpSearch(extraTargets: [route.gateway].compactMap { $0 }, timeout: 3)
        line("Risposte SSDP (IGD)", search.responses.isEmpty ? "nessuna" : search.responses.map { "\($0.key) → \($0.value)" }.joined(separator: "; "))
        if let error = search.sendError { line("Errore invio SSDP", error) }
        for (ip, location) in search.responses.sorted(by: { $0.key < $1.key }) {
            if let url = URL(string: location) {
                do {
                    let (data, response) = try await URLSession.shared.data(from: url)
                    line("Descrizione \(ip)", "HTTP \((response as? HTTPURLResponse)?.statusCode ?? 0), \(data.count) byte")
                } catch {
                    line("Descrizione \(ip)", "ERRORE: \(error.localizedDescription)")
                }
            }
            if let gw = await UPnPInspector.inspect(ip: ip, location: location) {
                line("Gateway UPnP", "\(gw.displayName): servizio \(gw.serviceType ?? "—"), tabella leggibile \(gw.mappingsReadable), porte \(gw.mappings.count)")
            } else {
                line("Gateway UPnP", "\(ip): ispezione fallita")
            }
        }
    }
}
