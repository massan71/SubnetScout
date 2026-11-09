import Foundation
import Darwin

public struct LocalInterface: Hashable, Sendable, Identifiable {
    public var name: String
    public var ip: String
    public var netmask: String
    public var prefixLength: Int
    /// Rete in notazione CIDR, es. "192.168.1.0/24".
    public var cidr: String

    public var id: String { "\(name)-\(ip)" }
    public var label: String { "\(name) · \(ip) · \(cidr)" }
}

public enum NetworkInfo {
    /// Interfacce IPv4 attive (escluso loopback), con en0/en1 in cima.
    public static func interfaces() -> [LocalInterface] {
        var result: [LocalInterface] = []
        var ifaddr: UnsafeMutablePointer<ifaddrs>?
        guard getifaddrs(&ifaddr) == 0, let first = ifaddr else { return [] }
        defer { freeifaddrs(ifaddr) }

        for ptr in sequence(first: first, next: { $0.pointee.ifa_next }) {
            let ifa = ptr.pointee
            let flags = Int32(ifa.ifa_flags)
            guard let addr = ifa.ifa_addr, addr.pointee.sa_family == UInt8(AF_INET),
                  let mask = ifa.ifa_netmask,
                  flags & IFF_UP != 0, flags & IFF_RUNNING != 0, flags & IFF_LOOPBACK == 0
            else { continue }

            let ip = addr.withMemoryRebound(to: sockaddr_in.self, capacity: 1) { UInt32(bigEndian: $0.pointee.sin_addr.s_addr) }
            let m = mask.withMemoryRebound(to: sockaddr_in.self, capacity: 1) { UInt32(bigEndian: $0.pointee.sin_addr.s_addr) }
            let prefix = m.nonzeroBitCount
            // Salta link-local (169.254/16) e interfacce punto-punto /32 (VPN).
            guard ip >> 16 != 0xA9FE, prefix < 32 else { continue }
            let network = ip & m
            result.append(LocalInterface(
                name: String(cString: ifa.ifa_name),
                ip: IPv4.format(ip),
                netmask: IPv4.format(m),
                prefixLength: prefix,
                cidr: "\(IPv4.format(network))/\(prefix)"
            ))
        }
        return result.sorted { rank($0.name) < rank($1.name) }
    }

    private static func rank(_ name: String) -> String {
        name.hasPrefix("en") ? "0\(name)" : "1\(name)"
    }

    /// Gateway predefinito (`route -n get default`).
    public static func defaultGateway() -> String? {
        defaultRoute().gateway
    }

    /// Gateway e interfaccia della rotta predefinita.
    public static func defaultRoute() -> (gateway: String?, interface: String?) {
        guard let out = try? Shell.run("/sbin/route", ["-n", "get", "default"]) else { return (nil, nil) }
        var gateway: String?, interface: String?
        for line in out.split(separator: "\n") {
            let trimmed = line.trimmingCharacters(in: .whitespaces)
            if trimmed.hasPrefix("gateway:") {
                gateway = trimmed.dropFirst("gateway:".count).trimmingCharacters(in: .whitespaces)
            } else if trimmed.hasPrefix("interface:") {
                interface = trimmed.dropFirst("interface:".count).trimmingCharacters(in: .whitespaces)
            }
        }
        return (gateway, interface)
    }

    public struct DHCPLease: Equatable, Sendable {
        public var server: String?
        public var routers: [String] = []
        public var dnsServers: [String] = []
    }

    /// Dati del lease DHCP dell'interfaccia (`ipconfig getpacket`), senza privilegi.
    public static func dhcpLease(interface: String) -> DHCPLease? {
        guard interface.allSatisfy({ $0.isLetter || $0.isNumber }),
              let out = try? Shell.run("/usr/sbin/ipconfig", ["getpacket", interface]), !out.isEmpty else { return nil }
        return parseDHCPPacket(out)
    }

    static func parseDHCPPacket(_ out: String) -> DHCPLease {
        // "server_identifier (ip): 10.0.1.1"   "router (ip_mult): {10.0.1.1}"
        func values(_ key: String) -> [String] {
            guard let line = out.split(separator: "\n").first(where: { $0.hasPrefix(key + " ") }),
                  let colon = line.firstIndex(of: ":") else { return [] }
            return line[line.index(after: colon)...]
                .trimmingCharacters(in: CharacterSet(charactersIn: " {}"))
                .split(separator: ",").map { $0.trimmingCharacters(in: .whitespaces) }.filter { !$0.isEmpty }
        }
        return DHCPLease(server: values("server_identifier").first,
                         routers: values("router"),
                         dnsServers: values("domain_name_server"))
    }

    /// Tabella ARP del Mac: IP → MAC normalizzato (AA:BB:CC:DD:EE:FF).
    /// Utile quando nmap gira senza root e non riporta gli indirizzi MAC.
    public static func arpTable() -> [String: String] {
        guard let out = try? Shell.run("/usr/sbin/arp", ["-an"]) else { return [:] }
        var table: [String: String] = [:]
        for line in out.split(separator: "\n") {
            // "? (192.168.1.5) at 2:3:4:a:b:c on en0 ifscope [ethernet]"
            let parts = line.split(separator: " ")
            guard parts.count >= 4, parts[2] == "at",
                  parts[1].hasPrefix("("), parts[1].hasSuffix(")") else { continue }
            let ip = String(parts[1].dropFirst().dropLast())
            guard let mac = normalizeMAC(String(parts[3])) else { continue }
            table[ip] = mac
        }
        return table
    }

    public static func normalizeMAC(_ raw: String) -> String? {
        let octets = raw.split(separator: ":")
        guard octets.count == 6 else { return nil }
        var out: [String] = []
        for o in octets {
            guard o.count <= 2, let v = UInt8(o, radix: 16) else { return nil }
            out.append(String(format: "%02X", v))
        }
        let mac = out.joined(separator: ":")
        return mac == "FF:FF:FF:FF:FF:FF" ? nil : mac
    }
}

enum Shell {
    static func run(_ path: String, _ args: [String]) throws -> String {
        let p = Process()
        p.executableURL = URL(fileURLWithPath: path)
        p.arguments = args
        let pipe = Pipe()
        p.standardOutput = pipe
        p.standardError = FileHandle.nullDevice
        try p.run()
        let data = pipe.fileHandleForReading.readDataToEndOfFile()
        p.waitUntilExit()
        return String(decoding: data, as: UTF8.self)
    }
}
