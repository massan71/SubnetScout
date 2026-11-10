import Foundation
import Testing
@testable import ScanKit

/// Answers NVD requests with a fixed JSON and counts the calls.
final class FakeNVD: URLProtocol, @unchecked Sendable {
    nonisolated(unsafe) static var requests: [URLRequest] = []
    nonisolated(unsafe) static var body = Data()
    nonisolated(unsafe) static var status = 200

    override class func canInit(with request: URLRequest) -> Bool { true }
    override class func canonicalRequest(for request: URLRequest) -> URLRequest { request }
    override func startLoading() {
        Self.requests.append(request)
        let resp = HTTPURLResponse(url: request.url!, statusCode: Self.status, httpVersion: nil, headerFields: nil)!
        client?.urlProtocol(self, didReceive: resp, cacheStoragePolicy: .notAllowed)
        client?.urlProtocol(self, didLoad: Self.body)
        client?.urlProtocolDidFinishLoading(self)
    }
    override func stopLoading() {}

    static func session() -> URLSession {
        let c = URLSessionConfiguration.ephemeral
        c.protocolClasses = [FakeNVD.self]
        return URLSession(configuration: c)
    }
}

let nvdSample = """
{"resultsPerPage":2,"totalResults":2,"vulnerabilities":[
 {"cve":{"id":"CVE-2023-48795","published":"2023-12-18T16:15:10.897","descriptions":[{"lang":"en","value":"Terrapin prefix truncation."}],
  "metrics":{"cvssMetricV31":[{"cvssData":{"baseScore":5.9,"baseSeverity":"MEDIUM"}}]}}},
 {"cve":{"id":"CVE-2023-38408","published":"2023-07-20T03:15:10.170","descriptions":[{"lang":"es","value":"x"},{"lang":"en","value":"ssh-agent PKCS#11 RCE."}],
  "metrics":{"cvssMetricV31":[{"cvssData":{"baseScore":9.8,"baseSeverity":"CRITICAL"}}]},
  "cisaExploitAdd":"2024-01-01","cisaVulnerabilityName":"OpenSSH agent RCE"}}
]}
"""

@Suite(.serialized) struct CVETests {
    @Test func convertsNmapCPEs() {
        #expect(CPE.nvdName(fromNmap: "cpe:/a:openbsd:openssh:9.3") == "cpe:2.3:a:openbsd:openssh:9.3:*:*:*:*:*:*:*")
        #expect(CPE.nvdName(fromNmap: "cpe:/a:openbsd:openssh:10.2p1") == "cpe:2.3:a:openbsd:openssh:10.2:p1:*:*:*:*:*:*")
        #expect(CPE.nvdName(fromNmap: "cpe:/a:lighttpd:lighttpd:1.4.35") == "cpe:2.3:a:lighttpd:lighttpd:1.4.35:*:*:*:*:*:*:*")
        #expect(CPE.nvdName(fromNmap: "cpe:/o:linux:linux_kernel") == nil, "no version, no query")
        #expect(CPE.nvdName(fromNmap: "cpe:/a:thekelleys:dnsmasq:unknown") == nil)
        #expect(CPE.nvdName(fromNmap: "cpe:/a:evil:x:1.0&foo=bar") == nil, "characters not allowed")
        #expect(CPE.label("cpe:2.3:a:openbsd:openssh:10.2:p1:*:*:*:*:*:*") == "openssh 10.2p1")
    }

    @Test func parserReadsServiceCPEs() throws {
        let xml = """
        <?xml version="1.0"?><nmaprun><host><status state="up"/><address addr="10.0.0.5" addrtype="ipv4"/><ports>
        <port protocol="tcp" portid="22"><state state="open"/><service name="ssh" product="OpenSSH" version="9.3">
        <cpe>cpe:/a:openbsd:openssh:9.3</cpe><cpe>cpe:/o:linux:linux_kernel</cpe></service></port>
        </ports><os><osmatch name="Linux" accuracy="90"><osclass><cpe>cpe:/o:linux:linux_kernel:5</cpe></osclass></osmatch></os></host></nmaprun>
        """
        let run = try NmapXMLParser.parse(Data(xml.utf8))
        #expect(run.hosts[0].ports[0].service?.cpes == ["cpe:/a:openbsd:openssh:9.3", "cpe:/o:linux:linux_kernel"])
        #expect(CVEAudit.queries(for: run.hosts) == ["cpe:2.3:a:openbsd:openssh:9.3:*:*:*:*:*:*:*"])
    }

    @Test func parsesNVDAndRanksKEVFirst() throws {
        let entries = try NVDClient.parse(Data(nvdSample.utf8))
        #expect(entries.map(\.id) == ["CVE-2023-38408", "CVE-2023-48795"])
        #expect(entries[0].knownExploited)
        #expect(entries[0].summary == "ssh-agent PKCS#11 RCE.")
        #expect(entries[0].subnetScoutSeverity == .critical)
        #expect(entries[1].subnetScoutSeverity == .medium)
        // An actively exploited CVE is at least "High" even with a low CVSS.
        let kevLow = CVEEntry(id: "x", cvss: 4.3, severity: "MEDIUM", summary: "", published: nil, knownExploited: true)
        #expect(kevLow.subnetScoutSeverity == .high)
    }

    @Test func findingsGroupPerServiceWithWorstSeverity() throws {
        let entries = try NVDClient.parse(Data(nvdSample.utf8))
        let host = Host(ip: "10.0.0.5", ports: [PortInfo(number: 22, proto: "tcp", state: "open",
            service: ServiceInfo(name: "ssh", product: "OpenSSH", version: "9.3", cpes: ["cpe:/a:openbsd:openssh:9.3"]))])
        let f = CVEAudit.findings(hosts: [host], vulnerabilities: ["cpe:2.3:a:openbsd:openssh:9.3:*:*:*:*:*:*:*": entries])
        #expect(f.count == 1)
        #expect(f[0].severity == .critical)
        #expect(f[0].port == "22/tcp")
        #expect(f[0].title == "2 known vulnerabilities in openssh 9.3")
        #expect(f[0].detail.contains("1 is actively exploited"))
        #expect(f[0].evidence?.hasPrefix("CVE-2023-38408 (9.8) KEV") == true)
    }

    @Test func lookupUsesCacheAndSendsOnlyTheCPE() async throws {
        FakeNVD.requests = []
        FakeNVD.body = Data(nvdSample.utf8)
        FakeNVD.status = 200
        let dir = FileManager.default.temporaryDirectory.appending(path: "nvd-\(UUID().uuidString)")
        defer { try? FileManager.default.removeItem(at: dir) }
        let cpe = "cpe:2.3:a:openbsd:openssh:9.3:*:*:*:*:*:*:*"
        let client = NVDClient(options: .init(apiKey: "test-key", cacheDirectory: dir), session: FakeNVD.session())

        let first = try await client.lookup([cpe, cpe])
        #expect(first[cpe]?.count == 2)
        #expect(FakeNVD.requests.count == 1, "duplicate CPEs queried once")
        let req = try #require(FakeNVD.requests.first)
        #expect(req.value(forHTTPHeaderField: "apiKey") == "test-key")
        let query = URLComponents(url: req.url!, resolvingAgainstBaseURL: false)!.queryItems!.map(\.name)
        #expect(Set(query) == ["virtualMatchString", "noRejected"], "no data other than the CPE")

        let again = try await NVDClient(options: .init(cacheDirectory: dir), session: FakeNVD.session()).lookup([cpe])
        #expect(again[cpe]?.count == 2)
        #expect(FakeNVD.requests.count == 1, "the second time the cache answers")
    }

    @Test func notFoundMeansNoCVEs() async throws {
        FakeNVD.requests = []
        FakeNVD.status = 404
        FakeNVD.body = Data()
        let dir = FileManager.default.temporaryDirectory.appending(path: "nvd-\(UUID().uuidString)")
        defer { try? FileManager.default.removeItem(at: dir) }
        let r = try await NVDClient(options: .init(cacheDirectory: dir), session: FakeNVD.session())
            .lookup(["cpe:2.3:a:x:y:1:*:*:*:*:*:*:*"])
        #expect(r.values.first?.isEmpty == true)
    }

    /// Optional, against the real NVD: SUBNETSCOUT_LIVE=1 swift test --filter liveNVD
    @Test(.enabled(if: ProcessInfo.processInfo.environment["SUBNETSCOUT_LIVE"] == "1"))
    func liveNVD() async throws {
        let dir = FileManager.default.temporaryDirectory.appending(path: "nvd-live-\(UUID().uuidString)")
        defer { try? FileManager.default.removeItem(at: dir) }
        let cpe = try #require(CPE.nvdName(fromNmap: "cpe:/a:openbsd:openssh:9.3"))
        let r = try await NVDClient(options: .init(cacheDirectory: dir)).lookup([cpe])
        let entries = r[cpe] ?? []
        print("NVD:", entries.count, "CVE, KEV:", entries.filter(\.knownExploited).map(\.id))
        #expect(entries.count > 10)
        #expect(entries.contains { $0.knownExploited })
    }
}
