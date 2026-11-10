import Foundation
import Testing
@testable import ScanKit

@Suite struct ParserTests {
    @Test func parsesHostsPortsScriptsAndOS() throws {
        let run = try NmapXMLParser.parse(Data(Fixtures.sampleXML.utf8))
        #expect(run.version == "7.95")
        #expect(run.hosts.count == 3, "the 'down' host is excluded")

        let router = try #require(run.hosts.first { $0.ip == "10.0.1.1" })
        #expect(router.mac == "BC:24:11:00:00:01")
        #expect(router.vendor == "Proxmox Server Solutions")
        #expect(router.hostnames == ["router.lan"])
        #expect(router.openPorts.map(\.number) == [23, 80, 443])
        #expect(router.ports.count == 4)
        #expect(router.bestOSGuess?.name == "Linux 4.15 - 5.19")
        #expect(router.latencyMs == 1.25)
        let https = try #require(router.openPorts.first { $0.number == 443 })
        #expect(https.service?.isTLS == true)
        #expect(https.script("ssl-cert")?.contains("Not valid after") == true)

        let nas = try #require(run.hosts.first { $0.ip == "10.0.1.20" })
        #expect(nas.hostScripts.map(\.id) == ["smb-protocols", "smb2-security-mode"])
    }

    @Test func truncatedXMLKeepsCompletedHosts() throws {
        let cut = Fixtures.sampleXML.components(separatedBy: "<host><status state=\"up\" reason=\"syn-ack\"/>")[0]
        let run = try NmapXMLParser.parse(Data(cut.utf8))
        #expect(run.hosts.count == 2)
    }

    @Test func progressIsExtractedFromTaskProgress() {
        let chunk = Data(#"<taskprogress task="Service scan" time="1" percent="42.50" remaining="10"/>"#.utf8)
        #expect(NmapRunner.progress(in: chunk) == 0.425)
    }
}

@Suite struct AuditTests {
    let hosts = try! NmapXMLParser.parse(Data(Fixtures.sampleXML.utf8)).hosts
    let now = ISO8601DateFormatter().date(from: "2026-11-09T12:00:00Z")!

    func rules(_ ip: String) -> Set<String> {
        Set(AuditEngine.audit(hosts, now: now).filter { $0.hostIP == ip }.map(\.ruleID))
    }

    @Test func routerFindings() {
        #expect(rules("10.0.1.1") == ["telnet", "http-cleartext", "tls-old", "tls-weak-ciphers",
                                      "cert-expired", "cert-self-signed"])
    }

    @Test func nasFindings() {
        #expect(rules("10.0.1.20") == ["ftp-anon", "db-exposed", "smbv1", "smb-signing"])
    }

    @Test func vncWithoutAuthIsCritical() {
        let f = AuditEngine.audit(hosts, now: now).first { $0.ruleID == "vnc-noauth" }
        #expect(f?.severity == .critical)
        #expect(f?.port == "5900/tcp")
    }

    @Test func findingsAreSortedBySeverity() {
        let sev = AuditEngine.audit(hosts, now: now).map(\.severity)
        #expect(sev == sev.sorted(by: >))
    }

    @Test func riskScoreAndGrade() {
        let findings = AuditEngine.audit(hosts, now: now)
        let risk = RiskSummary(hosts: hosts, findings: findings)
        // NAS = 68 (worst host) + (router 47 + VNC 40) / 10
        #expect(risk.hostScores["10.0.1.20"] == 68)
        #expect(risk.score == 76)
        #expect(risk.grade == "F")
        #expect(RiskSummary(hosts: hosts, findings: []).grade == "A")
    }
}

@Suite struct ProfileTests {
    @Test func profilesAvoidTopPortsOption() {
        for profile in ScanProfile.allCases {
            for priv in [false, true] {
                #expect(!profile.arguments(privileged: priv).contains("--top-ports"))
            }
        }
        #expect(ScanProfile.quick.arguments(privileged: false).contains("-F"))
    }

    /// With the protected nmap (official installer) the quick scan must really probe 100 ports.
    @Test(.enabled(if: FileManager.default.fileExists(atPath: TrustedNmap.adoptedRoot + "/bin/nmap")))
    func quickProfileWorksWithOfficialNmap() async throws {
        let n = try TrustedNmap.check(TrustedNmap.adoptedRoot + "/bin/nmap")
        let xml = try await NmapRunner(nmapPath: n.binary).runDirect(
            arguments: ScanProfile.quick.arguments(privileged: false) + ["--datadir", n.dataDir],
            targets: ["127.0.0.1"], onProgress: { _ in })
        #expect(String(decoding: xml, as: UTF8.self).contains("numservices=\"100\""))
    }
}

@Suite struct TargetTests {
    @Test func acceptsCommonForms() throws {
        #expect(try TargetParser.parse("192.168.1.0/24, 10.0.0.1-20  nas.local") == ["192.168.1.0/24", "10.0.0.1-20", "nas.local"])
    }

    @Test func rejectsOptionInjection() {
        #expect(throws: TargetError.self) { try TargetParser.parse("10.0.0.1 -iL /etc/passwd") }
        #expect(throws: TargetError.self) { try TargetParser.parse("10.0.0.1;rm") }
        #expect(throws: TargetError.self) { try TargetParser.parse("10.0.0.0/4") }
        #expect(throws: TargetError.self) { try TargetParser.parse("  ") }
    }

    @Test func hostCountEstimate() {
        #expect(TargetParser.estimatedHostCount(["10.0.0.0/24", "10.0.1.5"]) == 257)
    }
}

@Suite struct HelperTests {
    @Test func normalizesARPMac() {
        #expect(NetworkInfo.normalizeMAC("2:3:4:a:b:c") == "02:03:04:0A:0B:0C")
        #expect(NetworkInfo.normalizeMAC("ff:ff:ff:ff:ff:ff") == nil)
        #expect(NetworkInfo.normalizeMAC("(incomplete)") == nil)
    }

    @Test func vendorLookupAndRandomizedMAC() {
        let db = MACVendorDB(prefixes: ["BC2411": "Proxmox", "70B3D5123": "Long prefix Co"])
        #expect(db.vendor(for: "BC:24:11:00:00:01") == "Proxmox")
        #expect(db.vendor(for: "70:B3:D5:12:34:56") == "Long prefix Co")
        #expect(db.vendor(for: "BE:00:00:00:00:01") == "Private MAC (randomized)")
        #expect(db.vendor(for: "00:11:22:33:44:55") == nil)
    }

    @Test func diffDetectsNewHostsAndPorts() throws {
        let hosts = try NmapXMLParser.parse(Data(Fixtures.sampleXML.utf8)).hosts
        let t0 = Date(timeIntervalSince1970: 0)
        var older = hosts.dropLast().map { $0 }
        older[0].ports.removeAll { $0.number == 23 }
        let prev = ScanResult(target: "x", profile: .standard, privileged: false, startedAt: t0, finishedAt: t0,
                              hosts: older, findings: AuditEngine.audit(older))
        let curr = ScanResult(target: "x", profile: .standard, privileged: false, startedAt: t0, finishedAt: t0,
                              hosts: hosts, findings: AuditEngine.audit(hosts))
        let diff = ScanDiff(previous: prev, current: curr)
        #expect(diff.newHosts.map(\.ip) == ["10.0.1.9"])
        #expect(diff.openedPorts.map(\.port) == ["23/tcp"])
        #expect(diff.newFindings.contains { $0.ruleID == "telnet" })
    }

    @Test func reportEscapesHTMLAndCSV() throws {
        var hosts = try NmapXMLParser.parse(Data(Fixtures.sampleXML.utf8)).hosts
        hosts[0].hostnames = ["<script>alert(1)</script>"]
        let r = ScanResult(target: "10.0.1.0/24", profile: .standard, privileged: false,
                           startedAt: Date(), finishedAt: Date(), hosts: hosts, findings: AuditEngine.audit(hosts))
        let html = ReportGenerator.html(for: r)
        #expect(!html.contains("<script>alert"))
        #expect(html.contains("&lt;script&gt;"))
        #expect(ReportGenerator.csvField("=HYPERLINK(1)") == "'=HYPERLINK(1)")
        #expect(ReportGenerator.csv(for: r).split(separator: "\n").count > 3)
    }
}

@Suite struct TrustedNmapTests {
    @Test func parsesDylibsOfUniversalSystemBinary() throws {
        let libs = try TrustedNmap.dylibs(of: "/bin/ls")
        #expect(libs.contains("/usr/lib/libSystem.B.dylib"))
    }

    @Test func systemBinaryIsTrusted() throws {
        #expect(try TrustedNmap.checkBinary("/bin/ls") == "/bin/ls")
    }

    @Test(.enabled(if: FileManager.default.fileExists(atPath: "/opt/homebrew/bin/nmap")))
    func homebrewNmapIsRejected() {
        #expect(throws: TrustedNmap.Problem.self) { try TrustedNmap.check("/opt/homebrew/bin/nmap") }
        if case .failure(let p) = TrustedNmap.resolve(candidates: ["/opt/homebrew/bin/nmap"]) {
            #expect(p.localizedDescription.contains("is not owned by root"))
        } else {
            Issue.record("Homebrew nmap must not be trusted")
        }
    }

    @Test func userWritableFileIsRejected() throws {
        let dir = FileManager.default.temporaryDirectory.appending(path: "trusted-\(UUID().uuidString)")
        try FileManager.default.createDirectory(at: dir, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(at: dir) }
        let fake = dir.appending(path: "nmap")
        try FileManager.default.copyItem(atPath: "/bin/ls", toPath: fake.path)
        #expect(throws: TrustedNmap.Problem.self) { try TrustedNmap.checkBinary(fake.path) }
    }

    static let appNmap = "/Applications/nmap.app/Contents/Resources/bin/nmap"

    @Test(.enabled(if: FileManager.default.fileExists(atPath: appNmap)))
    func nmapAppInApplicationsIsRejectedButParsed() throws {
        // /Applications is writable by the admin group: not trusted in place.
        #expect(throws: TrustedNmap.Problem.untrustedPath("/Applications")) {
            try TrustedNmap.checkBinary(Self.appNmap)
        }
        let info = try TrustedNmap.machO(of: Self.appNmap)
        #expect(info.rpaths == ["@executable_path/../lib"])
        #expect(info.dylibs.contains("@rpath/libssl.3.dylib"))
    }

    /// If the helper already created the protected copy, it must be trusted (including @rpath libraries).
    @Test(.enabled(if: FileManager.default.fileExists(atPath: TrustedNmap.adoptedRoot + "/bin/nmap")))
    func adoptedCopyIsTrusted() throws {
        let r = try TrustedNmap.check(TrustedNmap.adoptedRoot + "/bin/nmap")
        #expect(r.dataDir == TrustedNmap.adoptedRoot + "/share/nmap")
        #expect(TrustedNmap.canAdopt == false)
        #expect((try? TrustedNmap.resolve().get())?.binary == r.binary)
    }

    @Test func missingBinaryReportsNotFound() {
        #expect(TrustedNmap.resolve(candidates: ["/nonexistent/nmap"]) == .failure(.notFound))
    }
}

/// Really runs nmap, but only against 127.0.0.1. Skipped if nmap is not installed.
@Suite struct IntegrationTests {
    @Test(.enabled(if: NmapLocator.find() != nil)) func quickScanOfLocalhost() async throws {
        let engine = ScanEngine(nmapPath: NmapLocator.find()!)
        let result = try await engine.scan(targets: ["127.0.0.1"], profile: .quick, privileged: false)
        #expect(result.hosts.count == 1)
        #expect(result.hosts.first?.ip == "127.0.0.1")
        #expect(result.nmapVersion != nil)
    }
}
