import Foundation

/// Predefined scan profiles. The arguments change depending on whether nmap runs as root
/// (SYN scan, OS detection, UDP) or as a normal user (connect scan).
public enum ScanProfile: String, Codable, CaseIterable, Identifiable, Sendable {
    case discovery
    case quick
    case standard
    case full

    public var id: String { rawValue }

    public var name: String {
        switch self {
        case .discovery: "Discovery"
        case .quick: "Quick"
        case .standard: "Standard + audit"
        case .full: "Full + audit"
        }
    }

    public var summary: String {
        switch self {
        case .discovery: "Finds active devices only (no ports)."
        case .quick: "Top 100 TCP ports with quick service detection."
        case .standard: "Top 1000 TCP ports, service versions and safe audit scripts."
        case .full: "All 65535 TCP ports (+ main UDP ports as administrator) and audit. Slow."
        }
    }

    public var scansPorts: Bool { self != .discovery }

    /// NSE scripts used for the audit: all belong to the `safe`/`default`/`discovery` categories.
    static let auditScriptsTCP = [
        "ftp-anon", "ssl-cert", "ssl-enum-ciphers",
        "smb-protocols", "smb2-security-mode",
        "sshv1", "ssh2-enum-algos",
        "http-title", "vnc-info", "rdp-enum-encryption",
        "http-security-headers", "http-methods", "ssl-dh-params", "ssh-hostkey",
    ]
    static let auditScriptsUDP = ["snmp-info", "dns-recursion", "upnp-info"]
    /// Broadcast scripts ("safe" category), run once before the hosts. They require root.
    static let networkScriptsPrivileged = ["broadcast-dhcp-discover"]
    /// The DHCP probe uses the Mac's real MAC: many routers ignore random MACs.
    static let networkScriptArgs = "broadcast-dhcp-discover.mac=native"

    /// UDP ports probed in the full profile (with privileges only).
    static let udpPorts = "53,67,123,137,161,500,1900,5353"

    public func arguments(privileged: Bool) -> [String] {
        var args: [String] = ["-T4", "--max-retries", "2"]
        switch self {
        case .discovery:
            args += ["-sn"]
        // No --top-ports: the official nmap 7.993 package always rejects it
        // ("--top-ports should be an integer between 1 and 65535").
        // -F = top 100; without a port specification nmap already uses the top 1000.
        case .quick:
            args += ["-F", "-sV", "--version-light"]
            if privileged { args += ["-sS"] }
        case .standard:
            let scripts = Self.auditScriptsTCP + (privileged ? Self.networkScriptsPrivileged : [])
            args += ["-sV", "--script", scripts.joined(separator: ",")]
            if privileged { args += ["--script-args", Self.networkScriptArgs] }
            if privileged { args += ["-sS", "-O", "--osscan-limit"] }
        case .full:
            if privileged {
                args += ["-sS", "-sU", "-O", "--osscan-limit",
                         "-p", "T:1-65535,U:\(Self.udpPorts)",
                         "--script", (Self.auditScriptsTCP + Self.auditScriptsUDP + Self.networkScriptsPrivileged)
                            .joined(separator: ","),
                         "--script-args", Self.networkScriptArgs]
            } else {
                args += ["-p-", "--script", Self.auditScriptsTCP.joined(separator: ",")]
            }
            args += ["-sV"]
        }
        return args
    }
}

// MARK: - Target validation

public enum TargetError: LocalizedError, Equatable {
    case empty
    case invalid(String)

    public var errorDescription: String? {
        switch self {
        case .empty: "Enter at least one target (e.g. 192.168.1.0/24)."
        case .invalid(let t): "Invalid target: “\(t)”. Use an IP, a range (10.0.0.1-50), CIDR or a hostname."
        }
    }
}

public enum TargetParser {
    /// Splits the string into targets and rejects anything nmap could
    /// interpret as an option (e.g. "-iL /etc/passwd").
    public static func parse(_ input: String) throws -> [String] {
        let tokens = input
            .split { $0 == " " || $0 == "," || $0 == "\n" || $0 == "\t" }
            .map(String.init)
        guard !tokens.isEmpty else { throw TargetError.empty }
        let allowed = CharacterSet(charactersIn: "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789.-:/_")
        for t in tokens {
            guard !t.hasPrefix("-"),
                  t.unicodeScalars.allSatisfy(allowed.contains),
                  t.count <= 253 else { throw TargetError.invalid(t) }
            if let slash = t.firstIndex(of: "/") {
                guard let prefix = Int(t[t.index(after: slash)...]), (8...32).contains(prefix) else {
                    throw TargetError.invalid(t)
                }
            }
        }
        return tokens
    }

    /// Approximate number of addresses covered (to warn about huge scans).
    public static func estimatedHostCount(_ targets: [String]) -> Int {
        targets.reduce(0) { sum, t in
            if let slash = t.firstIndex(of: "/"), let p = Int(t[t.index(after: slash)...]) {
                return sum + (1 << (32 - p))
            }
            return sum + 1
        }
    }
}
