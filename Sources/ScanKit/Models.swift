import Foundation

// MARK: - Severità

public enum Severity: Int, Codable, CaseIterable, Comparable, Sendable {
    case info = 0, low, medium, high, critical

    public static func < (a: Severity, b: Severity) -> Bool { a.rawValue < b.rawValue }

    public var label: String {
        switch self {
        case .info: "Info"
        case .low: "Bassa"
        case .medium: "Media"
        case .high: "Alta"
        case .critical: "Critica"
        }
    }

    /// Peso usato nel punteggio di rischio (0–100).
    public var weight: Int {
        switch self {
        case .info: 0
        case .low: 3
        case .medium: 8
        case .high: 20
        case .critical: 40
        }
    }
}

// MARK: - Porte e servizi

public struct ScriptOutput: Codable, Hashable, Sendable {
    public var id: String
    public var output: String

    public init(id: String, output: String) {
        self.id = id
        self.output = output
    }
}

public struct ServiceInfo: Codable, Hashable, Sendable {
    public var name: String?
    public var product: String?
    public var version: String?
    public var extraInfo: String?
    /// "ssl" quando nmap ha rilevato un servizio dentro TLS.
    public var tunnel: String?

    public init(name: String? = nil, product: String? = nil, version: String? = nil,
                extraInfo: String? = nil, tunnel: String? = nil) {
        self.name = name
        self.product = product
        self.version = version
        self.extraInfo = extraInfo
        self.tunnel = tunnel
    }

    /// "OpenSSH 9.6 (protocol 2.0)"
    public var productSummary: String {
        [product, version, extraInfo.map { "(\($0))" }]
            .compactMap { $0 }
            .filter { !$0.isEmpty }
            .joined(separator: " ")
    }

    public var isTLS: Bool { tunnel == "ssl" || (name?.contains("https") ?? false) || (name?.hasPrefix("ssl") ?? false) }
}

public struct PortInfo: Codable, Hashable, Sendable, Identifiable {
    public var number: Int
    public var proto: String
    public var state: String
    public var reason: String?
    public var service: ServiceInfo?
    public var scripts: [ScriptOutput]

    public init(number: Int, proto: String, state: String, reason: String? = nil,
                service: ServiceInfo? = nil, scripts: [ScriptOutput] = []) {
        self.number = number
        self.proto = proto
        self.state = state
        self.reason = reason
        self.service = service
        self.scripts = scripts
    }

    public var id: String { "\(number)/\(proto)" }
    public var isOpen: Bool { state == "open" }
    public var serviceName: String { service?.name ?? "" }

    public func script(_ id: String) -> String? {
        scripts.first { $0.id == id }?.output
    }
}

public struct OSGuess: Codable, Hashable, Sendable {
    public var name: String
    public var accuracy: Int

    public init(name: String, accuracy: Int) {
        self.name = name
        self.accuracy = accuracy
    }
}

// MARK: - Host

public struct Host: Codable, Hashable, Sendable, Identifiable {
    public var ip: String
    public var mac: String?
    public var vendor: String?
    public var hostnames: [String]
    public var ports: [PortInfo]
    public var hostScripts: [ScriptOutput]
    public var osGuesses: [OSGuess]
    /// Round-trip time in millisecondi, se disponibile.
    public var latencyMs: Double?
    public var isGateway: Bool
    public var isLocalMachine: Bool

    public init(ip: String, mac: String? = nil, vendor: String? = nil, hostnames: [String] = [],
                ports: [PortInfo] = [], hostScripts: [ScriptOutput] = [], osGuesses: [OSGuess] = [],
                latencyMs: Double? = nil, isGateway: Bool = false, isLocalMachine: Bool = false) {
        self.ip = ip
        self.mac = mac
        self.vendor = vendor
        self.hostnames = hostnames
        self.ports = ports
        self.hostScripts = hostScripts
        self.osGuesses = osGuesses
        self.latencyMs = latencyMs
        self.isGateway = isGateway
        self.isLocalMachine = isLocalMachine
    }

    public var id: String { ip }
    public var openPorts: [PortInfo] { ports.filter(\.isOpen) }
    public var displayName: String { hostnames.first ?? ip }
    public var bestOSGuess: OSGuess? { osGuesses.max { $0.accuracy < $1.accuracy } }

    /// Chiave stabile per riconoscere un dispositivo tra scansioni (il MAC se c'è, altrimenti l'IP).
    public var deviceKey: String { mac ?? ip }

    public func hostScript(_ id: String) -> String? {
        hostScripts.first { $0.id == id }?.output
    }

    public func hasOpen(_ number: Int, proto: String = "tcp") -> Bool {
        ports.contains { $0.number == number && $0.proto == proto && $0.isOpen }
    }

    /// Chiave numerica per ordinare gli IPv4 correttamente (10.0.0.9 < 10.0.0.10).
    public var ipSortKey: UInt32 { IPv4.parse(ip) ?? .max }
}

// MARK: - Finding

public struct Finding: Codable, Hashable, Sendable, Identifiable {
    public var ruleID: String
    public var severity: Severity
    public var title: String
    public var detail: String
    public var remediation: String
    public var hostIP: String
    /// es. "445/tcp"; nil per i finding a livello di host.
    public var port: String?
    public var evidence: String?

    public init(ruleID: String, severity: Severity, title: String, detail: String, remediation: String,
                hostIP: String, port: String? = nil, evidence: String? = nil) {
        self.ruleID = ruleID
        self.severity = severity
        self.title = title
        self.detail = detail
        self.remediation = remediation
        self.hostIP = hostIP
        self.port = port
        self.evidence = evidence
    }

    public var id: String { "\(ruleID)|\(hostIP)|\(port ?? "-")" }
}

// MARK: - Risultato di una scansione

public struct ScanResult: Codable, Hashable, Sendable, Identifiable {
    public var id: UUID
    public var target: String
    public var profile: ScanProfile
    public var privileged: Bool
    public var startedAt: Date
    public var finishedAt: Date
    public var nmapVersion: String?
    public var nmapArgs: String?
    public var hosts: [Host]
    public var findings: [Finding]

    public init(id: UUID = UUID(), target: String, profile: ScanProfile, privileged: Bool,
                startedAt: Date, finishedAt: Date, nmapVersion: String? = nil, nmapArgs: String? = nil,
                hosts: [Host], findings: [Finding]) {
        self.id = id
        self.target = target
        self.profile = profile
        self.privileged = privileged
        self.startedAt = startedAt
        self.finishedAt = finishedAt
        self.nmapVersion = nmapVersion
        self.nmapArgs = nmapArgs
        self.hosts = hosts
        self.findings = findings
    }

    public var duration: TimeInterval { finishedAt.timeIntervalSince(startedAt) }
    public var risk: RiskSummary { RiskSummary(hosts: hosts, findings: findings) }

    public func findings(for host: Host) -> [Finding] {
        findings.filter { $0.hostIP == host.ip }.sorted { $0.severity > $1.severity }
    }
}

// MARK: - Rischio

public struct RiskSummary: Hashable, Sendable {
    public let score: Int
    public let grade: String
    public let counts: [Severity: Int]
    public let hostScores: [String: Int]

    public init(hosts: [Host], findings: [Finding]) {
        var perHost: [String: Int] = [:]
        var counts: [Severity: Int] = [:]
        for f in findings {
            perHost[f.hostIP, default: 0] += f.severity.weight
            counts[f.severity, default: 0] += 1
        }
        self.hostScores = perHost.mapValues { min(100, $0) }
        self.counts = counts
        // Il punteggio di rete è guidato dall'host peggiore, più un contributo
        // per quanti altri host hanno problemi.
        let sorted = hostScores.values.sorted(by: >)
        let worst = sorted.first ?? 0
        let others = sorted.dropFirst().reduce(0, +)
        self.score = min(100, worst + others / 10)
        self.grade = switch score {
        case 0: "A"
        case 1...10: "B"
        case 11...25: "C"
        case 26...50: "D"
        default: "F"
        }
    }

    public func score(for host: Host) -> Int { hostScores[host.ip] ?? 0 }
}

// MARK: - IPv4 helper

public enum IPv4 {
    public static func parse(_ s: String) -> UInt32? {
        let parts = s.split(separator: ".")
        guard parts.count == 4 else { return nil }
        var value: UInt32 = 0
        for p in parts {
            guard let n = UInt32(p), n <= 255 else { return nil }
            value = value << 8 | n
        }
        return value
    }

    public static func format(_ v: UInt32) -> String {
        "\(v >> 24 & 255).\(v >> 16 & 255).\(v >> 8 & 255).\(v & 255)"
    }
}
