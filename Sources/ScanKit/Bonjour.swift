import Foundation
import dnssd

/// Information a device announces over Bonjour/mDNS.
public struct BonjourDevice: Codable, Hashable, Sendable {
    public var ip: String
    /// Instance names (e.g. "HP LaserJet MFP M139w (Living room)", "Kitchen").
    public var names: [String]
    /// .local host (e.g. "hp-laserjet.local.").
    public var hostname: String?
    /// Service types (e.g. "_ipp._tcp", "_airplay._tcp").
    public var services: [String]
    /// Model from the TXT records (model, md, ty, product…).
    public var model: String?

    public init(ip: String, names: [String] = [], hostname: String? = nil, services: [String] = [], model: String? = nil) {
        self.ip = ip
        self.names = names
        self.hostname = hostname
        self.services = services
        self.model = model
    }

    /// The most descriptive name: prefers printer/AirPlay names over technical ones.
    public var bestName: String? {
        let readable = names.filter { !$0.isEmpty && !Self.looksGenerated($0) }
        return readable.min { $0.count < $1.count } ?? model
    }

    /// Auto-generated names: hex only, or with a long identifier.
    static func looksGenerated(_ s: String) -> Bool {
        if s.allSatisfy({ $0.isHexDigit || $0 == "-" || $0 == ":" }) { return true }
        return s.range(of: "[0-9a-fA-F]{12,}", options: .regularExpression) != nil
    }
}

/// DNS-SD discovery through mDNSResponder (the system Bonjour API): no
/// connections to the devices and no packet parsing of our own.
/// In the app it can be blocked by the Local Network permission; in the helper it cannot.
public enum BonjourScanner {
    /// Common types on a home or office network.
    public static let serviceTypes = [
        "_device-info._tcp", "_http._tcp", "_https._tcp", "_ipp._tcp", "_ipps._tcp", "_printer._tcp",
        "_pdl-datastream._tcp", "_uscan._tcp", "_scanner._tcp", "_airplay._tcp", "_raop._tcp",
        "_companion-link._tcp", "_googlecast._tcp", "_spotify-connect._tcp", "_sonos._tcp",
        "_smb._tcp", "_afpovertcp._tcp", "_adisk._tcp", "_ssh._tcp", "_sftp-ssh._tcp", "_rfb._tcp",
        "_workstation._tcp", "_hap._tcp", "_homekit._tcp", "_matter._tcp", "_matterc._udp",
        "_shelly._tcp", "_home-assistant._tcp", "_esphomelib._tcp", "_mqtt._tcp", "_hue._tcp",
        "_amzn-wplay._tcp", "_androidtvremote2._tcp", "_daap._tcp", "_touch-able._tcp",
    ]

    public static func discover(timeout: TimeInterval = 4) -> [String: BonjourDevice] {
        let collector = Collector()
        let ctx = Unmanaged.passUnretained(collector).toOpaque()
        collector.queue.sync {
            for type in serviceTypes {
                var ref: DNSServiceRef?
                if DNSServiceBrowse(&ref, 0, 0, type, "local.", browseReply, ctx) == kDNSServiceErr_NoError, let ref {
                    DNSServiceSetDispatchQueue(ref, collector.queue)
                    collector.refs.append(ref)
                }
            }
        }
        Thread.sleep(forTimeInterval: timeout)
        return collector.queue.sync {
            collector.refs.forEach { DNSServiceRefDeallocate($0) }
            collector.refs.removeAll()
            return collector.devices
        }
    }

    // MARK: State (accessed only from the serial queue)

    final class Collector: @unchecked Sendable {
        let queue = DispatchQueue(label: "subnetscout.bonjour")
        var refs: [DNSServiceRef] = []
        var devices: [String: BonjourDevice] = [:]
        /// Resolved services waiting for an address, per .local host.
        var pending: [String: [(name: String, type: String, model: String?)]] = [:]
        var resolvedHosts: [String: [String]] = [:]
        var seen = Set<String>()
        var contexts: [ResolveContext] = []

        func add(ip: String, host: String, entries: [(name: String, type: String, model: String?)]) {
            var d = devices[ip] ?? BonjourDevice(ip: ip)
            d.hostname = d.hostname ?? host
            for e in entries {
                if !d.names.contains(e.name) { d.names.append(e.name) }
                let t = e.type.replacingOccurrences(of: ".local.", with: "").trimmingCharacters(in: CharacterSet(charactersIn: "."))
                if !d.services.contains(t) { d.services.append(t) }
                if d.model == nil, let m = e.model, !m.isEmpty { d.model = m }
            }
            devices[ip] = d
        }
    }

    /// Useful values from the TXT records.
    static func model(fromTXT txt: [String: String]) -> String? {
        for key in ["product", "ty", "md", "model", "usb_MDL", "modelName"] {
            if let v = txt[key]?.trimmingCharacters(in: CharacterSet(charactersIn: "() ")), !v.isEmpty { return v }
        }
        return nil
    }

    /// DNS-format TXT record: a sequence of length-prefixed (≤ 255) "key=value" strings.
    static func parseTXT(_ ptr: UnsafePointer<UInt8>?, length: Int) -> [String: String] {
        guard let ptr, length > 0 else { return [:] }
        var out: [String: String] = [:]
        var i = 0
        while i < length {
            let n = Int(ptr[i])
            i += 1
            guard n > 0, i + n <= length else { break }
            let s = String(decoding: UnsafeBufferPointer(start: ptr + i, count: n), as: UTF8.self)
            if let eq = s.firstIndex(of: "=") {
                out[String(s[..<eq])] = String(s[s.index(after: eq)...])
            }
            i += n
        }
        return out
    }
}

// MARK: - C callbacks (no captures: the context arrives as a pointer)

/// Context of a resolution: which service the reply refers to.
final class ResolveContext {
    unowned let collector: BonjourScanner.Collector
    let name: String
    let type: String
    init(_ c: BonjourScanner.Collector, name: String, type: String) { collector = c; self.name = name; self.type = type }
}

private func collector(_ ctx: UnsafeMutableRawPointer?) -> BonjourScanner.Collector? {
    ctx.map { Unmanaged<BonjourScanner.Collector>.fromOpaque($0).takeUnretainedValue() }
}

private let browseReply: DNSServiceBrowseReply = { _, flags, ifIndex, err, name, type, domain, ctx in
    guard err == kDNSServiceErr_NoError, flags & kDNSServiceFlagsAdd != 0,
          let c = collector(ctx), let name, let type, let domain else { return }
    let instance = String(cString: name), regtype = String(cString: type)
    guard c.seen.insert("\(instance)|\(regtype)").inserted else { return }
    let rc = ResolveContext(c, name: instance, type: regtype)
    c.contexts.append(rc)   // kept alive until the end of the discovery
    var ref: DNSServiceRef?
    if DNSServiceResolve(&ref, 0, ifIndex, name, type, domain, resolveReply,
                         Unmanaged.passUnretained(rc).toOpaque()) == kDNSServiceErr_NoError, let ref {
        DNSServiceSetDispatchQueue(ref, c.queue)
        c.refs.append(ref)
    }
}

private let resolveReply: DNSServiceResolveReply = { _, _, ifIndex, err, _, host, _, txtLen, txt, ctx in
    guard err == kDNSServiceErr_NoError, let ctx, let host else { return }
    let rc = Unmanaged<ResolveContext>.fromOpaque(ctx).takeUnretainedValue()
    let c = rc.collector
    let hostName = String(cString: host)
    let item = (name: rc.name, type: rc.type,
                model: BonjourScanner.model(fromTXT: BonjourScanner.parseTXT(txt, length: Int(txtLen))))

    if let ips = c.resolvedHosts[hostName] {
        ips.forEach { c.add(ip: $0, host: hostName, entries: [item]) }
        return
    }
    let first = c.pending[hostName] == nil
    c.pending[hostName, default: []].append(item)
    guard first else { return }
    var ref: DNSServiceRef?
    if DNSServiceGetAddrInfo(&ref, 0, ifIndex, DNSServiceProtocol(kDNSServiceProtocol_IPv4), host, addrReply,
                             Unmanaged.passUnretained(c).toOpaque()) == kDNSServiceErr_NoError, let ref {
        DNSServiceSetDispatchQueue(ref, c.queue)
        c.refs.append(ref)
    }
}

private let addrReply: DNSServiceGetAddrInfoReply = { _, _, _, err, host, address, _, ctx in
    guard err == kDNSServiceErr_NoError, let c = collector(ctx), let host, let address,
          address.pointee.sa_family == sa_family_t(AF_INET) else { return }
    let hostName = String(cString: host)
    let ip = address.withMemoryRebound(to: sockaddr_in.self, capacity: 1) {
        IPv4.format(UInt32(bigEndian: $0.pointee.sin_addr.s_addr))
    }
    guard ip != "0.0.0.0" else { return }
    if !(c.resolvedHosts[hostName]?.contains(ip) ?? false) { c.resolvedHosts[hostName, default: []].append(ip) }
    c.add(ip: ip, host: hostName, entries: c.pending[hostName] ?? [])
}

/// "Printer\032HP\.lan" → "Printer HP.lan" (DNS decimal escapes and backslashes).
func unescapeDNS(_ s: String) -> String {
    var out = ""
    var it = Array(s.unicodeScalars)[...]
    var bytes: [UInt8] = []
    func flush() { if !bytes.isEmpty { out += String(decoding: bytes, as: UTF8.self); bytes.removeAll() } }
    while let ch = it.popFirst() {
        if ch == "\\" {
            if it.count >= 3, let v = UInt8(String(String.UnicodeScalarView(it.prefix(3)))) {
                bytes.append(v); it = it.dropFirst(3); continue
            }
            if let next = it.popFirst() { flush(); out.unicodeScalars.append(next) }
        } else {
            flush(); out.unicodeScalars.append(ch)
        }
    }
    flush()
    return out
}
