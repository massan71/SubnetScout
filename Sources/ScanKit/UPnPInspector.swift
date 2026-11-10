import Foundation
import Darwin
import os

private let upnpLog = Logger(subsystem: "net.sangalli.SubnetScout", category: "upnp")

/// Finds the UPnP routers (Internet Gateway Devices) on the LAN and reads, read-only,
/// their port forwarding table: these are the ports that devices
/// opened to the Internet by themselves.
///
/// Replies come from the network and are not trustworthy: the description URL
/// must be http and point to the same IP that replied, documents have
/// size limits and the XML does not resolve external entities.
public enum UPnPInspector {
    static let ssdpAddress = "239.255.255.250"
    static let maxMappings = 128
    static let maxDocumentBytes = 512 * 1024

    public enum DiscoveryError: LocalizedError, Equatable {
        /// macOS blocked the send: usually the Local Network permission is missing.
        case sendFailed(String)

        public var errorDescription: String? {
            switch self {
            case .sendFailed(let reason):
                "UPnP discovery failed (\(reason)). Check that SubnetScout is allowed in System Settings › Privacy & Security › Local Network."
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

    /// IP → LOCATION for every device that announces itself as an Internet Gateway Device.
    /// `sendError` is set if no packet went out.
    public static func ssdpSearch(extraTargets: [String], timeout: TimeInterval) -> (responses: [String: String], sendError: String?) {
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
        // UDP can get lost and some routers ignore requests sent close together: the send
        // is repeated after a second, as the SSDP specification recommends.
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
            guard n > 0 else {
                if n < 0, errno != EAGAIN, errno != EWOULDBLOCK { upnpLog.info("SSDP recvfrom: \(String(cString: strerror(errno)), privacy: .public)") }
                continue
            }
            let ip = IPv4.format(UInt32(bigEndian: from.sin_addr.s_addr))
            let text = String(decoding: buffer[0..<n], as: UTF8.self)
            if let location = header("location", in: text), found[ip] == nil { found[ip] = location }
        }
        upnpLog.info("SSDP: \(sent, privacy: .public) sends, error \(sendError ?? "-", privacy: .public), responses \(found.keys.sorted().joined(separator: ","), privacy: .public)")
        return (found, sent == 0 ? sendError : nil)
    }

    /// Returns the error description, or nil if the packet went out.
    private static func send(_ fd: Int32, _ message: String, to ip: String) -> String? {
        var addr = sockaddr_in()
        addr.sin_family = sa_family_t(AF_INET)
        addr.sin_port = in_port_t(1900).bigEndian
        guard inet_pton(AF_INET, ip, &addr.sin_addr) == 1 else { return "invalid address" }
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

    // MARK: Description and port mappings

    public static func inspect(ip: String, location: String) async -> UPnPGateway? {
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
                // Error 713 (SpecifiedArrayIndexInvalid) = end of the table.
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

    /// An empty table answers 500 with UPnP error 713: we consider it readable.
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

/// The parts of the device description we need.
struct DeviceDescription {
    struct Service { var serviceType: String; var controlURL: String }

    var friendlyName: String?
    var manufacturer: String?
    var modelName: String?
    var services: [Service] = []

    /// Prefers WANIPConnection, then WANPPPConnection.
    var wanService: Service? {
        services.first { $0.serviceType.contains("WANIPConnection") }
            ?? services.first { $0.serviceType.contains("WANPPPConnection") }
    }

    /// String-scanning parser (no libxml2): it also runs in the root helper
    /// on data coming from the network, so it must be simple and memory-safe.
    static func parse(_ xml: String) -> DeviceDescription {
        var d = DeviceDescription()
        d.friendlyName = UPnPInspector.tagValue("friendlyName", in: xml)?.nonEmpty
        d.manufacturer = UPnPInspector.tagValue("manufacturer", in: xml)?.nonEmpty
        d.modelName = UPnPInspector.tagValue("modelName", in: xml)?.nonEmpty
        var rest = xml[...]
        while d.services.count < 64,
              let open = rest.range(of: "<service>"),
              let close = rest.range(of: "</service>", range: open.upperBound..<rest.endIndex) {
            let block = String(rest[open.upperBound..<close.lowerBound])
            if let type = UPnPInspector.tagValue("serviceType", in: block),
               let control = UPnPInspector.tagValue("controlURL", in: block) {
                d.services.append(Service(serviceType: type, controlURL: control))
            }
            rest = rest[close.upperBound...]
        }
        return d
    }
}
