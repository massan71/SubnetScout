import Foundation
import Testing
@testable import ScanKit

@Suite struct NetworkMapTests {
    func scan(_ hosts: [ScanKit.Host], findings: [Finding] = []) -> ScanResult {
        ScanResult(target: "10.0.0.0/24", profile: .quick, privileged: false, startedAt: .now, finishedAt: .now,
                   hosts: hosts, findings: findings)
    }

    func sampleHosts() -> [ScanKit.Host] {
        var hosts = [ScanKit.Host(ip: "10.0.0.1", isGateway: true)]
        for i in 2...30 {
            hosts.append(ScanKit.Host(ip: "10.0.0.\(i)", hostnames: ["d\(i).lan"],
                                      bonjourServices: i % 3 == 0 ? ["_ipp._tcp"] : i % 3 == 1 ? ["_shelly._tcp"] : nil))
        }
        return hosts
    }

    @Test func placesEveryDeviceAroundTheGateway() {
        let map = NetworkMap(result: scan(sampleHosts()))
        #expect(map.center?.ip == "10.0.0.1")
        #expect(map.center?.x == 0 && map.center?.y == 0)
        #expect(map.nodes.count == 29)
        #expect(Set(map.allNodes.map(\.ip)).count == 30, "nessun dispositivo duplicato o perso")
        for n in map.nodes {
            let r = (n.x * n.x + n.y * n.y).squareRoot()
            #expect(r > 0.95 && r < 1.35, "\(n.ip) fuori dagli anelli: \(r)")
        }
    }

    @Test func sectorsDoNotOverlapAndCoverTheCircle() {
        let map = NetworkMap(result: scan(sampleHosts()))
        #expect(map.groups.map(\.kind) == [.printer, .iot, .unknown], "ordine stabile per tipo")
        for (a, b) in zip(map.groups, map.groups.dropFirst()) { #expect(a.endAngle <= b.startAngle) }
        let covered = map.groups.reduce(0) { $0 + ($1.endAngle - $1.startAngle) }
        #expect(covered < 2 * .pi && covered > 1.8 * .pi)
        #expect(map.groups.reduce(0) { $0 + $1.count } == 29)
    }

    @Test func nodesCarryWorstSeverityAndGatewayMayBeMissing() {
        let hosts = [ScanKit.Host(ip: "10.0.0.5"), ScanKit.Host(ip: "10.0.0.6")]
        let f = [Finding(ruleID: "a", severity: .low, title: "", detail: "", remediation: "", hostIP: "10.0.0.5"),
                 Finding(ruleID: "b", severity: .high, title: "", detail: "", remediation: "", hostIP: "10.0.0.5")]
        let map = NetworkMap(result: scan(hosts, findings: f))
        #expect(map.center == nil)
        #expect(map.nodes.first { $0.ip == "10.0.0.5" }?.severity == .high)
        #expect(map.nodes.first { $0.ip == "10.0.0.6" }?.severity == nil)
    }

    @Test func reportSVGEscapesNames() {
        var hosts = sampleHosts()
        hosts[3].bonjourName = "<script>x</script>"
        let html = ReportGenerator.html(for: scan(hosts))
        #expect(html.contains("<svg class=\"map\""))
        #expect(!html.contains("<script>x"))
        #expect(html.contains("&lt;script&gt;x"))
    }
}
