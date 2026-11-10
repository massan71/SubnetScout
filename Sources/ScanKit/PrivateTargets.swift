import Foundation
import Darwin

/// Restricts targets to private networks: the root helper must not be usable
/// to scan public addresses (even if a client managed to talk to it).
public enum PrivateTargets {
    public enum Rejection: LocalizedError, Equatable {
        case notPrivate(String)
        case unresolvable(String)

        public var errorDescription: String? {
            switch self {
            case .notPrivate(let t):
                "“\(t)” is not a private network address: the helper only scans local networks."
            case .unresolvable(let t):
                "Cannot resolve “\(t)”."
            }
        }
    }

    /// 10/8, 172.16/12, 192.168/16, 169.254/16 (link-local), 100.64/10 (CGNAT), 127/8.
    static let ipv4Blocks: [(UInt32, UInt32)] = [
        (0x0A00_0000, 0x0AFF_FFFF), (0xAC10_0000, 0xAC1F_FFFF), (0xC0A8_0000, 0xC0A8_FFFF),
        (0xA9FE_0000, 0xA9FE_FFFF), (0x6440_0000, 0x647F_FFFF), (0x7F00_0000, 0x7FFF_FFFF),
    ]

    /// Checks the targets and returns the ones to pass to nmap: hostnames are
    /// replaced by the resolved addresses (all private), so a different DNS answer
    /// at scan time cannot lead outside the LAN.
    public static func validate(_ targets: [String]) throws -> [String] {
        var out: [String] = []
        for t in targets {
            if let (lo, hi) = ipv4Span(t) {
                guard isPrivate(lo: lo, hi: hi) else { throw Rejection.notPrivate(t) }
                out.append(t)
            } else if t.contains(":") {
                guard isPrivateIPv6(t) else { throw Rejection.notPrivate(t) }
                out.append(t)
            } else {
                let addrs = resolve(t)
                guard !addrs.isEmpty else { throw Rejection.unresolvable(t) }
                for a in addrs {
                    let ok = a.contains(":") ? isPrivateIPv6(a) : (IPv4.parse(a).map { isPrivate(lo: $0, hi: $0) } ?? false)
                    guard ok else { throw Rejection.notPrivate("\(t) → \(a)") }
                    if !out.contains(a) { out.append(a) }
                }
            }
        }
        return out
    }

    public static func allPrivate(_ targets: [String]) -> Bool {
        (try? validate(targets)) != nil
    }

    static func isPrivate(lo: UInt32, hi: UInt32) -> Bool {
        ipv4Blocks.contains { lo >= $0.0 && hi <= $0.1 }
    }

    /// Range covered by an nmap IPv4 target: "10.0.0.1", "10.0.0.0/24",
    /// "10.0.1.1-50", "10.0.0-3.*", "192.168.1.1,5,9". nil if it is not IPv4.
    static func ipv4Span(_ t: String) -> (UInt32, UInt32)? {
        if let slash = t.firstIndex(of: "/") {
            guard let base = IPv4.parse(String(t[..<slash])), let p = Int(t[t.index(after: slash)...]), (0...32).contains(p)
            else { return nil }
            let mask: UInt32 = p == 0 ? 0 : ~UInt32(0) << (32 - p)
            return (base & mask, (base & mask) | ~mask)
        }
        let octets = t.split(separator: ".", omittingEmptySubsequences: false)
        guard octets.count == 4 else { return nil }
        var lo: UInt32 = 0, hi: UInt32 = 0
        for o in octets {
            guard let (a, b) = octetSpan(String(o)) else { return nil }
            lo = lo << 8 | a
            hi = hi << 8 | b
        }
        return (lo, hi)
    }

    private static func octetSpan(_ s: String) -> (UInt32, UInt32)? {
        if s == "*" { return (0, 255) }
        var values: [UInt32] = []
        for part in s.split(separator: ",", omittingEmptySubsequences: false) {
            let ends = part.split(separator: "-", omittingEmptySubsequences: false)
            switch ends.count {
            case 1:
                guard let v = UInt32(ends[0]), v <= 255 else { return nil }
                values.append(v)
            case 2:
                let a = ends[0].isEmpty ? 0 : UInt32(ends[0])
                let b = ends[1].isEmpty ? 255 : UInt32(ends[1])
                guard let a, let b, a <= b, b <= 255 else { return nil }
                values += [a, b]
            default:
                return nil
            }
        }
        guard let mn = values.min(), let mx = values.max() else { return nil }
        return (mn, mx)
    }

    /// fe80::/10 (link-local), fc00::/7 (ULA), ::1. With a prefix, the block must stay inside.
    static func isPrivateIPv6(_ t: String) -> Bool {
        var addrPart = t, prefix = 128
        if let slash = t.firstIndex(of: "/") {
            guard let p = Int(t[t.index(after: slash)...]), (0...128).contains(p) else { return false }
            addrPart = String(t[..<slash])
            prefix = p
        }
        var a = in6_addr()
        guard inet_pton(AF_INET6, addrPart.split(separator: "%").first.map(String.init) ?? addrPart, &a) == 1 else { return false }
        let b = withUnsafeBytes(of: a) { Array($0) }
        if b[0..<15].allSatisfy({ $0 == 0 }) && b[15] == 1 { return prefix == 128 }
        if b[0] == 0xFE && b[1] & 0xC0 == 0x80 { return prefix >= 10 }
        if b[0] & 0xFE == 0xFC { return prefix >= 7 }
        return false
    }

    static func resolve(_ host: String) -> [String] {
        var hints = addrinfo()
        hints.ai_socktype = SOCK_STREAM
        var res: UnsafeMutablePointer<addrinfo>?
        guard getaddrinfo(host, nil, &hints, &res) == 0, let first = res else { return [] }
        defer { freeaddrinfo(res) }
        var out: [String] = []
        for ai in sequence(first: first, next: { $0.pointee.ai_next }) {
            var buf = [CChar](repeating: 0, count: Int(NI_MAXHOST))
            if getnameinfo(ai.pointee.ai_addr, ai.pointee.ai_addrlen, &buf, socklen_t(buf.count), nil, 0, NI_NUMERICHOST) == 0 {
                let s = String(cString: buf)
                if !out.contains(s) { out.append(s) }
            }
        }
        return out
    }
}
