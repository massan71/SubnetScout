import Foundation
import Testing
@testable import ScanKit

@Suite struct ChangeSummaryTests {
    func scan(_ hosts: [Host], _ findings: [Finding] = []) -> ScanResult {
        ScanResult(target: "192.168.1.0/24", profile: .quick, privileged: false, startedAt: .now, finishedAt: .now,
                   hosts: hosts, findings: findings)
    }
    let a = Host(ip: "192.168.1.10", mac: "AA:00:00:00:00:10",
                 ports: [PortInfo(number: 22, proto: "tcp", state: "open")])
    let b = Host(ip: "192.168.1.20", mac: "AA:00:00:00:00:20")
    let c = Host(ip: "192.168.1.30", mac: "AA:00:00:00:00:30")

    func finding(_ rule: String, _ sev: Severity, _ ip: String) -> Finding {
        Finding(ruleID: rule, severity: sev, title: rule, detail: "", remediation: "", hostIP: ip)
    }

    @Test func firstScanIsBaselineWithoutNotification() {
        let s = ChangeSummary(previous: nil, current: scan([a, b]), trusted: [])
        #expect(s.isEmpty)
    }

    @Test func countsUntrustedNewDevicesAndOpenedPorts() {
        var a2 = a
        a2.ports.append(PortInfo(number: 23, proto: "tcp", state: "open"))
        let s = ChangeSummary(previous: scan([a]), current: scan([a2, b, c]), trusted: ["AA:00:00:00:00:30"])
        #expect(s.newDevices == 1, "c is known")
        #expect(s.openedPorts == 1)
        #expect(s.body == "1 new device · 1 opened port")
        #expect(!s.body.contains("192.168"), "no IPs in notifications")
    }

    @Test func severityThresholdAndCVEsAreSeparated() {
        let prev = scan([a])
        let curr = scan([a], [finding("telnet", .high, a.ip), finding("http-cleartext", .low, a.ip),
                              finding("known-cve", .critical, a.ip)])
        let s = ChangeSummary(previous: prev, current: curr, trusted: [])
        #expect(s.newIssues == 1, "low severity does not notify")
        #expect(s.newCVEServices == 1)
        #expect(s.worst == .critical)
        #expect(s.title.contains("security issues"))
        #expect(s.body == "1 new issue · 1 service with new CVEs (highest severity: critical)")
    }

    @Test func unchangedNetworkIsEmpty() {
        let f = [finding("telnet", .high, a.ip)]
        #expect(ChangeSummary(previous: scan([a, b], f), current: scan([a, b], f), trusted: []).isEmpty)
    }
}
