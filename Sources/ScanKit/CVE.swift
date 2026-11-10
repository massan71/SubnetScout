import Foundation
import CryptoKit

// MARK: - Modelli

/// Una vulnerabilità nota (dal database NVD del NIST).
public struct CVEEntry: Codable, Hashable, Sendable, Identifiable {
    public var id: String
    public var cvss: Double?
    /// "CRITICAL", "HIGH", "MEDIUM", "LOW" secondo la metrica più recente disponibile.
    public var severity: String?
    public var summary: String
    public var published: String?
    /// Presente nel catalogo CISA KEV: sfruttata attivamente.
    public var knownExploited: Bool
    public var kevName: String?

    public init(id: String, cvss: Double?, severity: String?, summary: String, published: String?,
                knownExploited: Bool, kevName: String? = nil) {
        self.id = id
        self.cvss = cvss
        self.severity = severity
        self.summary = summary
        self.published = published
        self.knownExploited = knownExploited
        self.kevName = kevName
    }

    public var url: URL { URL(string: "https://nvd.nist.gov/vuln/detail/\(id)")! }

    /// Gravità SubnetScout: da CVSS; le CVE sfruttate attivamente sono almeno «Alta».
    public var subnetScoutSeverity: Severity {
        let base: Severity = switch cvss ?? 0 {
        case 9...: .critical
        case 7..<9: .high
        case 4..<7: .medium
        case 0.1..<4: .low
        default: .info
        }
        return knownExploited ? max(base, .high) : base
    }
}

// MARK: - CPE

public enum CPE {
    /// Converte un CPE 2.2 di nmap in CPE 2.3 per NVD, solo se ha vendor, prodotto e
    /// una versione utilizzabile. "cpe:/a:openbsd:openssh:10.2p1" →
    /// "cpe:2.3:a:openbsd:openssh:10.2:p1:*:*:*:*:*:*" (OpenSSH separa la «portable release»).
    public static func nvdName(fromNmap cpe: String) -> String? {
        guard cpe.hasPrefix("cpe:/") else { return nil }
        let parts = cpe.dropFirst(5).split(separator: ":", omittingEmptySubsequences: false).map(String.init)
        guard parts.count >= 4, ["a", "o", "h"].contains(parts[0]) else { return nil }
        let part = parts[0], vendor = parts[1], product = parts[2]
        var version = parts[3].lowercased()
        var update = parts.count > 4 && !parts[4].isEmpty ? parts[4] : "*"
        let allowed = CharacterSet(charactersIn: "abcdefghijklmnopqrstuvwxyz0123456789._-+~")
        guard !vendor.isEmpty, !product.isEmpty, !version.isEmpty, version != "unknown", version != "-",
              version.first?.isNumber == true,
              (vendor + product + version).lowercased().unicodeScalars.allSatisfy(allowed.contains)
        else { return nil }
        if product == "openssh", update == "*",
           let p = version.range(of: #"p\d+$"#, options: .regularExpression) {
            update = String(version[p])
            version = String(version[..<p.lowerBound])
        }
        return "cpe:2.3:\(part):\(vendor):\(product):\(version):\(update):*:*:*:*:*:*"
    }

    /// "cpe:2.3:a:openbsd:openssh:9.3:*:…" → "openssh 9.3"
    public static func label(_ nvdName: String) -> String {
        let p = nvdName.split(separator: ":").map(String.init)
        guard p.count >= 6 else { return nvdName }
        let update = p.count > 6 && p[6] != "*" ? p[6] : ""
        return "\(p[4].replacingOccurrences(of: "_", with: " ")) \(p[5])\(update)"
    }
}

// MARK: - Client NVD

/// Interroga l'API CVE 2.0 di NVD. Viene inviato solo il CPE (prodotto e versione),
/// mai indirizzi o nomi dei dispositivi. Le risposte restano in cache su disco.
public actor NVDClient {
    public struct Options: Sendable {
        public var apiKey: String?
        public var cacheDirectory: URL
        public var cacheTTL: TimeInterval
        public var maxQueries: Int

        public init(apiKey: String? = nil, cacheDirectory: URL = NVDClient.defaultCacheDirectory,
                    cacheTTL: TimeInterval = 7 * 86_400, maxQueries: Int = 80) {
            self.apiKey = apiKey?.isEmpty == true ? nil : apiKey
            self.cacheDirectory = cacheDirectory
            self.cacheTTL = cacheTTL
            self.maxQueries = maxQueries
        }
    }

    public enum LookupError: LocalizedError {
        case http(Int)
        case rateLimited

        public var errorDescription: String? {
            switch self {
            case .http(let code): "NVD ha risposto con errore HTTP \(code)."
            case .rateLimited: "NVD sta limitando le richieste: riprova tra qualche minuto o usa una chiave API."
            }
        }
    }

    public static let defaultCacheDirectory: URL =
        FileManager.default.urls(for: .cachesDirectory, in: .userDomainMask)[0]
            .appending(path: "SubnetScout/NVD", directoryHint: .isDirectory)

    static let endpoint = URL(string: "https://services.nvd.nist.gov/rest/json/cves/2.0")!

    let options: Options
    private let session: URLSession
    private var lastRequest: Date?

    public init(options: Options, session: URLSession = .shared) {
        self.options = options
        self.session = session
    }

    /// Senza chiave NVD ammette 5 richieste ogni 30 s, con chiave 50.
    var minimumInterval: TimeInterval { options.apiKey == nil ? 6.5 : 0.7 }

    /// CVE per ogni CPE (dalla cache quando è recente). `onStatus` riceve «i di n».
    public func lookup(_ cpes: [String], onStatus: @Sendable (Int, Int) -> Void = { _, _ in })
        async throws -> [String: [CVEEntry]] {
        let unique = Array(Set(cpes)).sorted().prefix(options.maxQueries)
        var out: [String: [CVEEntry]] = [:]
        for (i, cpe) in unique.enumerated() {
            try Task.checkCancellation()
            onStatus(i + 1, unique.count)
            if let cached = cached(cpe) {
                out[cpe] = cached
                continue
            }
            let entries = try await fetch(cpe)
            store(entries, for: cpe)
            out[cpe] = entries
        }
        return out
    }

    private func fetch(_ cpe: String) async throws -> [CVEEntry] {
        if let last = lastRequest {
            let wait = minimumInterval - Date().timeIntervalSince(last)
            if wait > 0 { try await Task.sleep(for: .seconds(wait)) }
        }
        var comps = URLComponents(url: Self.endpoint, resolvingAgainstBaseURL: false)!
        comps.queryItems = [URLQueryItem(name: "virtualMatchString", value: cpe),
                            URLQueryItem(name: "noRejected", value: nil)]
        var req = URLRequest(url: comps.url!, timeoutInterval: 30)
        if let key = options.apiKey { req.setValue(key, forHTTPHeaderField: "apiKey") }

        var attempt = 0
        while true {
            lastRequest = Date()
            let (data, response) = try await session.data(for: req)
            let status = (response as? HTTPURLResponse)?.statusCode ?? 0
            switch status {
            case 200:
                return try Self.parse(data)
            case 403, 429, 503 where attempt < 2:
                attempt += 1
                try await Task.sleep(for: .seconds(30))
            case 403, 429:
                throw LookupError.rateLimited
            case 404:
                return []
            default:
                throw LookupError.http(status)
            }
        }
    }

    // MARK: Parsing

    private struct Response: Decodable {
        struct Item: Decodable { let cve: CVE }
        struct CVE: Decodable {
            let id: String
            let published: String?
            let descriptions: [Description]?
            let metrics: Metrics?
            let cisaExploitAdd: String?
            let cisaVulnerabilityName: String?
        }
        struct Description: Decodable { let lang: String; let value: String }
        struct Metrics: Decodable {
            let cvssMetricV40: [Metric]?
            let cvssMetricV31: [Metric]?
            let cvssMetricV30: [Metric]?
            let cvssMetricV2: [MetricV2]?
        }
        struct Metric: Decodable { let cvssData: Data }
        struct MetricV2: Decodable { let cvssData: DataV2; let baseSeverity: String? }
        struct Data: Decodable { let baseScore: Double; let baseSeverity: String? }
        struct DataV2: Decodable { let baseScore: Double }
        let vulnerabilities: [Item]?
    }

    static func parse(_ data: Foundation.Data) throws -> [CVEEntry] {
        let r = try JSONDecoder().decode(Response.self, from: data)
        return (r.vulnerabilities ?? []).map { item in
            let c = item.cve
            let m = c.metrics
            let v3 = m?.cvssMetricV40?.first ?? m?.cvssMetricV31?.first ?? m?.cvssMetricV30?.first
            let score = v3?.cvssData.baseScore ?? m?.cvssMetricV2?.first?.cvssData.baseScore
            let sev = v3?.cvssData.baseSeverity ?? m?.cvssMetricV2?.first?.baseSeverity
            let text = c.descriptions?.first { $0.lang == "en" }?.value ?? c.descriptions?.first?.value ?? ""
            return CVEEntry(id: c.id, cvss: score, severity: sev, summary: text,
                            published: c.published.map { String($0.prefix(10)) },
                            knownExploited: c.cisaExploitAdd != nil, kevName: c.cisaVulnerabilityName)
        }
        .sorted { ($0.knownExploited ? 1 : 0, $0.cvss ?? 0) > ($1.knownExploited ? 1 : 0, $1.cvss ?? 0) }
    }

    // MARK: Cache

    private func cacheURL(_ cpe: String) -> URL {
        let name = SHA256.hash(data: Data(cpe.utf8)).prefix(16).map { String(format: "%02x", $0) }.joined()
        return options.cacheDirectory.appending(path: "\(name).json")
    }

    private struct CacheFile: Codable { let cpe: String; let fetched: Date; let entries: [CVEEntry] }

    private func cached(_ cpe: String) -> [CVEEntry]? {
        guard let data = try? Data(contentsOf: cacheURL(cpe)),
              let file = try? JSONDecoder().decode(CacheFile.self, from: data),
              file.cpe == cpe, Date().timeIntervalSince(file.fetched) < options.cacheTTL else { return nil }
        return file.entries
    }

    private func store(_ entries: [CVEEntry], for cpe: String) {
        try? FileManager.default.createDirectory(at: options.cacheDirectory, withIntermediateDirectories: true)
        try? FileManager.default.setAttributes([.posixPermissions: 0o700], ofItemAtPath: options.cacheDirectory.path)
        if let data = try? JSONEncoder().encode(CacheFile(cpe: cpe, fetched: Date(), entries: entries)) {
            try? data.write(to: cacheURL(cpe), options: [.atomic])
        }
    }

    public static func clearCache(at dir: URL = defaultCacheDirectory) {
        try? FileManager.default.removeItem(at: dir)
    }
}

// MARK: - Problemi

public enum CVEAudit {
    /// CPE 2.3 da interrogare per ogni porta aperta (porta → CPE).
    public static func queries(for hosts: [Host]) -> [String] {
        hosts.flatMap { h in h.openPorts.flatMap { ($0.service?.cpes ?? []).compactMap(CPE.nvdName(fromNmap:)) } }
    }

    /// Un problema per servizio vulnerabile (host + porta), con la gravità della CVE peggiore.
    public static func findings(hosts: [Host], vulnerabilities: [String: [CVEEntry]]) -> [Finding] {
        var out: [Finding] = []
        for h in hosts {
            for p in h.openPorts {
                let names = (p.service?.cpes ?? []).compactMap(CPE.nvdName(fromNmap:))
                var entries: [CVEEntry] = []
                for n in names { entries += vulnerabilities[n] ?? [] }
                entries = Dictionary(entries.map { ($0.id, $0) }, uniquingKeysWith: { a, _ in a }).values
                    .sorted { ($0.knownExploited ? 1 : 0, $0.cvss ?? 0) > ($1.knownExploited ? 1 : 0, $1.cvss ?? 0) }
                guard let worst = entries.first, let name = names.first else { continue }
                let kev = entries.filter(\.knownExploited)
                let product = p.service?.productSummary.isEmpty == false ? p.service!.productSummary : CPE.label(name)
                let maxScore = entries.compactMap(\.cvss).max().map { String(format: "%.1f", $0) } ?? "n/d"
                out.append(Finding(
                    ruleID: "known-cve",
                    severity: entries.map(\.subnetScoutSeverity).max() ?? worst.subnetScoutSeverity,
                    title: "\(entries.count) \(entries.count == 1 ? "vulnerabilità nota" : "vulnerabilità note") in \(CPE.label(name))",
                    detail: "La versione dichiarata (\(product)) è interessata da \(entries.count) CVE, CVSS massimo \(maxScore)"
                        + (kev.isEmpty ? "." : "; \(kev.count) \(kev.count == 1 ? "sfruttata" : "sfruttate") attivamente (CISA KEV).")
                        + " Corrispondenza basata sulla versione: i dispositivi che applicano patch senza cambiare versione possono essere falsi positivi.",
                    remediation: "Aggiorna il software o il firmware del dispositivo all'ultima versione del produttore.",
                    hostIP: h.ip, port: p.id,
                    evidence: entries.prefix(5).map { "\($0.id)\($0.cvss.map { " (\(String(format: "%.1f", $0)))" } ?? "")\($0.knownExploited ? " KEV" : "")" }
                        .joined(separator: ", ")))
            }
        }
        return out
    }

    /// CVE di una porta, per la vista di dettaglio.
    public static func entries(for port: PortInfo, in vulnerabilities: [String: [CVEEntry]]?) -> [CVEEntry] {
        guard let vulnerabilities else { return [] }
        let all = (port.service?.cpes ?? []).compactMap(CPE.nvdName(fromNmap:)).flatMap { vulnerabilities[$0] ?? [] }
        return Dictionary(all.map { ($0.id, $0) }, uniquingKeysWith: { a, _ in a }).values
            .sorted { ($0.knownExploited ? 1 : 0, $0.cvss ?? 0) > ($1.knownExploited ? 1 : 0, $1.cvss ?? 0) }
    }
}
