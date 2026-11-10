import Foundation

/// State of the network at scan time: used by the rules that are not about
/// a single service (ARP spoofing, rogue DHCP, UPnP…)
/// and for comparison with later scans.
public struct NetworkContext: Codable, Hashable, Sendable {
    public var interface: String?
    public var localIP: String?
    public var gatewayIP: String?
    public var gatewayMAC: String?
    /// DHCP server that assigned the address to this Mac.
    public var dhcpServer: String?
    /// Router and DNS received from DHCP.
    public var dhcpRouters: [String]
    public var dnsServers: [String]
    /// Offers collected by `broadcast-dhcp-discover` (as administrator only).
    public var dhcpOffers: [DHCPOffer]
    public var dhcpProbed: Bool
    /// UPnP Internet Gateway Devices found on the LAN.
    public var upnpGateways: [UPnPGateway]
    public var upnpProbed: Bool
    /// true if macOS blocked access to the local network (empty ARP table):
    /// the ARP spoofing and UPnP checks are not reliable.
    public var localNetworkBlocked: Bool?
    /// Why the UPnP lookup was not possible (e.g. Local Network permission denied).
    public var upnpError: String?

    public init(interface: String? = nil, localIP: String? = nil, gatewayIP: String? = nil, gatewayMAC: String? = nil,
                dhcpServer: String? = nil, dhcpRouters: [String] = [], dnsServers: [String] = [],
                dhcpOffers: [DHCPOffer] = [], dhcpProbed: Bool = false,
                upnpGateways: [UPnPGateway] = [], upnpProbed: Bool = false) {
        self.interface = interface
        self.localIP = localIP
        self.gatewayIP = gatewayIP
        self.gatewayMAC = gatewayMAC
        self.dhcpServer = dhcpServer
        self.dhcpRouters = dhcpRouters
        self.dnsServers = dnsServers
        self.dhcpOffers = dhcpOffers
        self.dhcpProbed = dhcpProbed
        self.upnpGateways = upnpGateways
        self.upnpProbed = upnpProbed
    }
}

public struct DHCPOffer: Codable, Hashable, Sendable {
    public var server: String
    public var offeredIP: String?
    public var routers: [String]
    public var dnsServers: [String]
    public var interface: String?

    public init(server: String, offeredIP: String? = nil, routers: [String] = [], dnsServers: [String] = [],
                interface: String? = nil) {
        self.server = server
        self.offeredIP = offeredIP
        self.routers = routers
        self.dnsServers = dnsServers
        self.interface = interface
    }

    /// Reads the output of `broadcast-dhcp-discover`:
    ///
    ///     Response 1 of 1:
    ///       Interface: en0
    ///       IP Offered: 10.0.1.240
    ///       Server Identifier: 10.0.1.1
    ///       Router: 10.0.1.1
    ///       Domain Name Server: 10.0.1.1, 1.1.1.1
    public static func parse(_ output: String) -> [DHCPOffer] {
        var offers: [DHCPOffer] = []
        var current: [String: String] = [:]
        func flush() {
            if let server = current["Server Identifier"] {
                offers.append(DHCPOffer(server: server,
                                        offeredIP: current["IP Offered"],
                                        routers: list(current["Router"]),
                                        dnsServers: list(current["Domain Name Server"]),
                                        interface: current["Interface"]))
            }
            current = [:]
        }
        for raw in output.split(separator: "\n") {
            let line = raw.trimmingCharacters(in: .whitespaces)
            if line.hasPrefix("Response ") { flush(); continue }
            guard let colon = line.firstIndex(of: ":") else { continue }
            let key = String(line[..<colon]).trimmingCharacters(in: .whitespaces)
            let value = String(line[line.index(after: colon)...]).trimmingCharacters(in: .whitespaces)
            if !value.isEmpty { current[key] = value }
        }
        flush()
        return offers
    }

    private static func list(_ s: String?) -> [String] {
        (s ?? "").split(separator: ",").map { $0.trimmingCharacters(in: .whitespaces) }.filter { !$0.isEmpty }
    }
}

public struct UPnPGateway: Codable, Hashable, Sendable, Identifiable {
    public var ip: String
    public var location: String
    public var friendlyName: String?
    public var manufacturer: String?
    public var model: String?
    /// WANIPConnection / WANPPPConnection service used to read the port mappings.
    public var serviceType: String?
    public var mappings: [UPnPPortMapping]
    /// false if the service exists but does not allow reading the table.
    public var mappingsReadable: Bool

    public init(ip: String, location: String, friendlyName: String? = nil, manufacturer: String? = nil,
                model: String? = nil, serviceType: String? = nil, mappings: [UPnPPortMapping] = [],
                mappingsReadable: Bool = false) {
        self.ip = ip
        self.location = location
        self.friendlyName = friendlyName
        self.manufacturer = manufacturer
        self.model = model
        self.serviceType = serviceType
        self.mappings = mappings
        self.mappingsReadable = mappingsReadable
    }

    public var id: String { ip }
    public var displayName: String {
        [manufacturer, model].compactMap { $0 }.joined(separator: " ").nonEmpty ?? friendlyName ?? ip
    }
}

public struct UPnPPortMapping: Codable, Hashable, Sendable {
    public var externalPort: Int
    public var proto: String
    public var internalClient: String
    public var internalPort: Int
    public var enabled: Bool
    public var description: String
    public var leaseSeconds: Int
    /// Allowed remote host; empty = anyone on the Internet.
    public var remoteHost: String

    public init(externalPort: Int, proto: String, internalClient: String, internalPort: Int, enabled: Bool,
                description: String, leaseSeconds: Int, remoteHost: String) {
        self.externalPort = externalPort
        self.proto = proto
        self.internalClient = internalClient
        self.internalPort = internalPort
        self.enabled = enabled
        self.description = description
        self.leaseSeconds = leaseSeconds
        self.remoteHost = remoteHost
    }
}

extension String {
    var nonEmpty: String? { isEmpty ? nil : self }
}
