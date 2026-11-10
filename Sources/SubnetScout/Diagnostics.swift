import Foundation
import ScanKit

/// Command-line diagnostics:
///
///     /Applications/SubnetScout.app/Contents/MacOS/SubnetScout --diagnose-network
///
/// Useful because the Local Network permission and App Transport Security apply to the app,
/// not to tests or to scripts launched from the terminal.
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
        line("Gateway / interface", "\(route.gateway ?? "—") / \(route.interface ?? "—")")
        let arp = NetworkInfo.arpTable()
        line("ARP table", "\(arp.count) entries" + (arp.isEmpty ? "  ⚠︎ empty: “Local Network” permission denied?" : ""))
        if let gw = route.gateway { line("Gateway MAC", arp[gw] ?? "—") }
        if let iface = route.interface, let lease = NetworkInfo.dhcpLease(interface: iface) {
            line("DHCP lease", "server \(lease.server ?? "—"), router \(lease.routers.joined(separator: ",")), DNS \(lease.dnsServers.joined(separator: ","))")
        }

        if HelperClient.isBundled, HelperClient.service.status == .enabled {
            do {
                let p = try await HelperClient.networkProbe()
                line("Helper probe", "\(p.arp.count) ARP entries, UPnP routers: \(p.upnpGateways.map { "\($0.displayName) (\($0.ip), \($0.mappings.count) ports)" }.joined(separator: "; ").isEmpty ? "none" : p.upnpGateways.map { "\($0.displayName) (\($0.ip), \($0.mappings.count) ports)" }.joined(separator: "; "))" + (p.upnpError.map { " · \($0)" } ?? ""))
                for (ip, d) in (p.bonjour ?? [:]).sorted(by: { (IPv4.parse($0.key) ?? 0) < (IPv4.parse($1.key) ?? 0) }) {
                    line("  Bonjour \(ip)", "\(d.bestName ?? "—") · \(d.model ?? "—") · \(d.services.prefix(3).joined(separator: ", "))")
                }
            } catch {
                line("Helper probe", "ERROR: \(error.localizedDescription)")
            }
        } else {
            line("Helper probe", "helper not active")
        }

        let search = UPnPInspector.ssdpSearch(extraTargets: [route.gateway].compactMap { $0 }, timeout: 3)
        line("SSDP responses (IGD)", search.responses.isEmpty ? "none" : search.responses.map { "\($0.key) → \($0.value)" }.joined(separator: "; "))
        if let error = search.sendError { line("SSDP send error", error) }
        for (ip, location) in search.responses.sorted(by: { $0.key < $1.key }) {
            if let url = URL(string: location) {
                do {
                    let (data, response) = try await URLSession.shared.data(from: url)
                    line("Description \(ip)", "HTTP \((response as? HTTPURLResponse)?.statusCode ?? 0), \(data.count) byte")
                } catch {
                    line("Description \(ip)", "ERROR: \(error.localizedDescription)")
                }
            }
            if let gw = await UPnPInspector.inspect(ip: ip, location: location) {
                line("Gateway UPnP", "\(gw.displayName): service \(gw.serviceType ?? "—"), table readable \(gw.mappingsReadable), ports \(gw.mappings.count)")
            } else {
                line("Gateway UPnP", "\(ip): inspection failed")
            }
        }
    }
}
