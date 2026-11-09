import Foundation

/// Stato della rete al momento della scansione: serve alle regole che non
/// riguardano un singolo servizio (ARP spoofing, DHCP non autorizzati, UPnP…)
/// e al confronto con le scansioni successive.
public struct NetworkContext: Codable, Hashable, Sendable {
    public var interface: String?
    public var localIP: String?
    public var gatewayIP: String?
    public var gatewayMAC: String?
    /// Server DHCP che ha assegnato l'indirizzo a questo Mac.
    public var dhcpServer: String?
    /// Router e DNS ricevuti dal DHCP.
    public var dhcpRouters: [String]
    public var dnsServers: [String]
    /// Offerte raccolte da `broadcast-dhcp-discover` (solo come amministratore).
    public var dhcpOffers: [DHCPOffer]
    public var dhcpProbed: Bool
    /// Dispositivi UPnP Internet Gateway trovati in LAN.
    public var upnpGateways: [UPnPGateway]
    public var upnpProbed: Bool
    /// true se macOS ha bloccato l'accesso alla rete locale (tabella ARP vuota):
    /// controllo ARP spoofing e UPnP non sono affidabili.
    public var localNetworkBlocked: Bool?
    /// Motivo per cui la ricerca UPnP non è stata possibile (es. permesso «Rete locale» negato).
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

    /// Legge l'output di `broadcast-dhcp-discover`:
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
    /// Servizio WANIPConnection / WANPPPConnection usato per leggere i port mapping.
    public var serviceType: String?
    public var mappings: [UPnPPortMapping]
    /// false se il servizio esiste ma non permette di leggere la tabella.
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
    /// Host remoto ammesso; vuoto = chiunque su Internet.
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
