import Foundation

/// Profili di scansione predefiniti. Gli argomenti cambiano se nmap gira come root
/// (SYN scan, OS detection, UDP) oppure come utente normale (connect scan).
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

    /// Script NSE usati per l'audit: tutti appartengono alle categorie `safe`/`default`/`discovery`.
    static let auditScriptsTCP = [
        "ftp-anon", "ssl-cert", "ssl-enum-ciphers",
        "smb-protocols", "smb2-security-mode",
        "sshv1", "ssh2-enum-algos",
        "http-title", "vnc-info", "rdp-enum-encryption",
        "http-security-headers", "http-methods", "ssl-dh-params", "ssh-hostkey",
    ]
    static let auditScriptsUDP = ["snmp-info", "dns-recursion", "upnp-info"]
    /// Script broadcast (categoria «safe»), eseguiti una volta prima degli host. Richiedono root.
    static let networkScriptsPrivileged = ["broadcast-dhcp-discover"]
    /// La sonda DHCP usa il MAC reale del Mac: molti router ignorano i MAC casuali.
    static let networkScriptArgs = "broadcast-dhcp-discover.mac=native"

    /// Porte UDP interrogate nel profilo completo (solo con privilegi).
    static let udpPorts = "53,67,123,137,161,500,1900,5353"

    public func arguments(privileged: Bool) -> [String] {
        var args: [String] = ["-T4", "--max-retries", "2"]
        switch self {
        case .discovery:
            args += ["-sn"]
        // Niente --top-ports: il pacchetto ufficiale nmap 7.993 lo rifiuta sempre
        // ("--top-ports should be an integer between 1 and 65535").
        // -F = top 100; senza specifica di porte nmap usa già le top 1000.
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

// MARK: - Validazione dei target

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
    /// Divide la stringa in target e rifiuta tutto ciò che potrebbe essere
    /// interpretato da nmap come un'opzione (es. "-iL /etc/passwd").
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

    /// Numero approssimativo di indirizzi coperti (per avvisare su scansioni enormi).
    public static func estimatedHostCount(_ targets: [String]) -> Int {
        targets.reduce(0) { sum, t in
            if let slash = t.firstIndex(of: "/"), let p = Int(t[t.index(after: slash)...]) {
                return sum + (1 << (32 - p))
            }
            return sum + 1
        }
    }
}
