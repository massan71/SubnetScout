import Foundation
import Darwin

/// Trova i router UPnP (Internet Gateway Device) della LAN e ne legge, in sola
/// lettura, la tabella dei port forwarding: sono le porte che i dispositivi
/// hanno aperto da soli verso Internet.
///
/// Le risposte arrivano dalla rete e non sono affidabili: l'URL di descrizione
/// deve essere http e puntare allo stesso IP che ha risposto, i documenti hanno
/// limiti di dimensione e l'XML non risolve entità esterne.
public enum UPnPInspector {
    static let ssdpAddress = "239.255.255.250"
    static let maxMappings = 128
    static let maxDocumentBytes = 512 * 1024

    public enum DiscoveryError: LocalizedError, Equatable {
        /// macOS ha bloccato l'invio: di solito manca il permesso «Rete locale».
        case sendFailed(String)

        public var errorDescription: String? {
            switch self {
            case .sendFailed(let reason):
                "Ricerca UPnP non riuscita (\(reason)). Controlla che SubnetScout abbia il permesso in Impostazioni di Sistema › Privacy e sicurezza › Rete locale."
            }
        }
    }

    public static func discover(extraTargets: [String] = [], timeout: TimeInterval = 3) async throws -> [UPnPGateway] {
        let search = await Task.detached { ssdpSearch(extraTargets: extraTargets, timeout: timeout) }.value
        if search.responses.isEmpty, let error = search.sendError { throw DiscoveryError.sendFailed(error) }
        var gateways: [UPnPGateway] = []
        for (ip, location) in search.responses.sorted(by: { $0.key < $1.key }) {
            if let gw = await inspect(ip: ip, location: location) { gateways.append(gw) }
        }
        return gateways
    }

    // MARK: SSDP

    /// IP → LOCATION per ogni dispositivo che si annuncia come Internet Gateway Device.
    /// `sendError` è valorizzato se nessun pacchetto è partito.
    static func ssdpSearch(extraTargets: [String], timeout: TimeInterval) -> (responses: [String: String], sendError: String?) {
        let fd = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP)
        guard fd >= 0 else { return ([:], String(cString: strerror(errno))) }
        defer { close(fd) }
        var tv = timeval(tv_sec: 0, tv_usec: 250_000)
        setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, socklen_t(MemoryLayout<timeval>.size))
        var ttl: UInt8 = 2
        setsockopt(fd, IPPROTO_IP, IP_MULTICAST_TTL, &ttl, socklen_t(MemoryLayout<UInt8>.size))

        var found: [String: String] = [:]
        var sent = 0
        var sendError: String?
        func sendAll() {
            for st in ["urn:schemas-upnp-org:device:InternetGatewayDevice:1",
                       "urn:schemas-upnp-org:device:InternetGatewayDevice:2"] {
                let msg = "M-SEARCH * HTTP/1.1\r\nHOST: 239.255.255.250:1900\r\nMAN: \"ssdp:discover\"\r\nMX: 2\r\nST: \(st)\r\n\r\n"
                for target in [ssdpAddress] + extraTargets {
                    if let error = send(fd, msg, to: target) { sendError = error } else { sent += 1 }
                }
            }
        }
        // UDP può perdersi e alcuni router ignorano richieste ravvicinate: si ripete
        // l'invio dopo un secondo, come raccomanda la specifica SSDP.
        sendAll()
        var resent = false
        let deadline = Date().addingTimeInterval(timeout)
        var buffer = [UInt8](repeating: 0, count: 8192)
        let start = Date()
        while Date() < deadline {
            if !resent, Date().timeIntervalSince(start) > 1 { sendAll(); resent = true }
            var from = sockaddr_in()
            var len = socklen_t(MemoryLayout<sockaddr_in>.size)
            let n = withUnsafeMutablePointer(to: &from) {
                $0.withMemoryRebound(to: sockaddr.self, capacity: 1) { recvfrom(fd, &buffer, buffer.count, 0, $0, &len) }
            }
            guard n > 0 else { continue }
            let ip = IPv4.format(UInt32(bigEndian: from.sin_addr.s_addr))
            let text = String(decoding: buffer[0..<n], as: UTF8.self)
            if let location = header("location", in: text), found[ip] == nil { found[ip] = location }
        }
        return (found, sent == 0 ? sendError : nil)
    }

    /// Restituisce la descrizione dell'errore, o nil se il pacchetto è partito.
    private static func send(_ fd: Int32, _ message: String, to ip: String) -> String? {
        var addr = sockaddr_in()
        addr.sin_family = sa_family_t(AF_INET)
        addr.sin_port = in_port_t(1900).bigEndian
        guard inet_pton(AF_INET, ip, &addr.sin_addr) == 1 else { return "indirizzo non valido" }
        let bytes = Array(message.utf8)
        let n = withUnsafePointer(to: &addr) {
            $0.withMemoryRebound(to: sockaddr.self, capacity: 1) {
                sendto(fd, bytes, bytes.count, 0, $0, socklen_t(MemoryLayout<sockaddr_in>.size))
            }
        }
        return n < 0 ? String(cString: strerror(errno)) : nil
    }

    static func header(_ name: String, in response: String) -> String? {
        for line in response.split(whereSeparator: \.isNewline) {
            guard let colon = line.firstIndex(of: ":") else { continue }
            if line[..<colon].trimmingCharacters(in: .whitespaces).lowercased() == name {
                return line[line.index(after: colon)...].trimmingCharacters(in: .whitespaces)
            }
        }
        return nil
    }

    // MARK: Descrizione e port mapping

    static func inspect(ip: String, location: String) async -> UPnPGateway? {
        guard let url = URL(string: location), url.scheme == "http", url.host == ip else { return nil }
        guard let xml = await fetch(URLRequest(url: url, timeoutInterval: 4)) else { return nil }
        let desc = DeviceDescription.parse(xml)
        var gw = UPnPGateway(ip: ip, location: location, friendlyName: desc.friendlyName,
                             manufacturer: desc.manufacturer, model: desc.modelName)
        guard let service = desc.wanService,
              let control = URL(string: service.controlURL, relativeTo: url)?.absoluteURL,
              control.host == ip else { return gw }
        gw.serviceType = service.serviceType

        var mappings: [UPnPPortMapping] = []
        var readable = false
        for index in 0..<maxMappings {
            guard let body = await soap(control, service: service.serviceType, action: "GetGenericPortMappingEntry",
                                        arguments: "<NewPortMappingIndex>\(index)</NewPortMappingIndex>") else {
                // Errore 713 (SpecifiedArrayIndexInvalid) = fine della tabella.
                if index == 0 { readable = await canReadTable(control, service: service.serviceType) }
                break
            }
            readable = true
            if let m = parseMapping(body) { mappings.append(m) }
        }
        gw.mappings = mappings
        gw.mappingsReadable = readable
        return gw
    }

    /// Una tabella vuota risponde 500 con errore UPnP 713: la consideriamo leggibile.
    private static func canReadTable(_ control: URL, service: String) async -> Bool {
        var req = soapRequest(control, service: service, action: "GetGenericPortMappingEntry",
                              arguments: "<NewPortMappingIndex>0</NewPortMappingIndex>")
        req.timeoutInterval = 4
        guard let (data, _) = try? await URLSession.shared.data(for: req) else { return false }
        return String(decoding: data.prefix(maxDocumentBytes), as: UTF8.self).contains("713")
    }

    static func parseMapping(_ xml: String) -> UPnPPortMapping? {
        func v(_ tag: String) -> String? { tagValue(tag, in: xml) }
        guard let ext = v("NewExternalPort").flatMap(Int.init), let client = v("NewInternalClient") else { return nil }
        return UPnPPortMapping(externalPort: ext,
                               proto: (v("NewProtocol") ?? "TCP").uppercased(),
                               internalClient: client,
                               internalPort: v("NewInternalPort").flatMap(Int.init) ?? ext,
                               enabled: v("NewEnabled").map { $0 == "1" || $0.lowercased() == "true" } ?? true,
                               description: v("NewPortMappingDescription") ?? "",
                               leaseSeconds: v("NewLeaseDuration").flatMap(Int.init) ?? 0,
                               remoteHost: v("NewRemoteHost") ?? "")
    }

    static func tagValue(_ tag: String, in xml: String) -> String? {
        guard let open = xml.range(of: "<\(tag)>"), let close = xml.range(of: "</\(tag)>", range: open.upperBound..<xml.endIndex)
        else { return nil }
        return String(xml[open.upperBound..<close.lowerBound])
            .replacingOccurrences(of: "&amp;", with: "&").replacingOccurrences(of: "&lt;", with: "<")
            .replacingOccurrences(of: "&gt;", with: ">").trimmingCharacters(in: .whitespacesAndNewlines)
    }

    private static func soapRequest(_ url: URL, service: String, action: String, arguments: String) -> URLRequest {
        var req = URLRequest(url: url, timeoutInterval: 4)
        req.httpMethod = "POST"
        req.setValue("text/xml; charset=\"utf-8\"", forHTTPHeaderField: "Content-Type")
        req.setValue("\"\(service)#\(action)\"", forHTTPHeaderField: "SOAPAction")
        req.httpBody = Data("""
        <?xml version="1.0"?><s:Envelope xmlns:s="http://schemas.xmlsoap.org/soap/envelope/" \
        s:encodingStyle="http://schemas.xmlsoap.org/soap/encoding/"><s:Body>\
        <u:\(action) xmlns:u="\(service)">\(arguments)</u:\(action)></s:Body></s:Envelope>
        """.utf8)
        return req
    }

    private static func soap(_ url: URL, service: String, action: String, arguments: String) async -> String? {
        await fetch(soapRequest(url, service: service, action: action, arguments: arguments))
    }

    private static func fetch(_ request: URLRequest) async -> String? {
        guard let (data, response) = try? await URLSession.shared.data(for: request),
              let http = response as? HTTPURLResponse, http.statusCode == 200,
              data.count <= maxDocumentBytes else { return nil }
        return String(decoding: data, as: UTF8.self)
    }
}

/// Parti del device description che ci servono.
struct DeviceDescription {
    struct Service { var serviceType: String; var controlURL: String }

    var friendlyName: String?
    var manufacturer: String?
    var modelName: String?
    var services: [Service] = []

    /// Preferisce WANIPConnection, poi WANPPPConnection.
    var wanService: Service? {
        services.first { $0.serviceType.contains("WANIPConnection") }
            ?? services.first { $0.serviceType.contains("WANPPPConnection") }
    }

    static func parse(_ xml: String) -> DeviceDescription {
        let delegate = Delegate()
        let parser = XMLParser(data: Data(xml.utf8))
        parser.shouldResolveExternalEntities = false
        parser.delegate = delegate
        parser.parse()
        return delegate.result
    }

    private final class Delegate: NSObject, XMLParserDelegate {
        var result = DeviceDescription()
        private var text = ""
        private var serviceType: String?
        private var controlURL: String?
        private var inService = false

        func parser(_ parser: XMLParser, didStartElement name: String, namespaceURI: String?,
                    qualifiedName: String?, attributes: [String: String]) {
            text = ""
            if name == "service" { inService = true; serviceType = nil; controlURL = nil }
        }

        func parser(_ parser: XMLParser, foundCharacters string: String) { text += string }

        func parser(_ parser: XMLParser, didEndElement name: String, namespaceURI: String?, qualifiedName: String?) {
            let value = text.trimmingCharacters(in: .whitespacesAndNewlines)
            switch name {
            case "friendlyName" where result.friendlyName == nil: result.friendlyName = value.nonEmpty
            case "manufacturer" where result.manufacturer == nil: result.manufacturer = value.nonEmpty
            case "modelName" where result.modelName == nil: result.modelName = value.nonEmpty
            case "serviceType" where inService: serviceType = value
            case "controlURL" where inService: controlURL = value
            case "service":
                if let serviceType, let controlURL { result.services.append(Service(serviceType: serviceType, controlURL: controlURL)) }
                inService = false
            default: break
            }
            text = ""
        }
    }
}
