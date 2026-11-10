import SwiftUI
import AppKit
import ScanKit

struct HostDetailView: View {
    @Environment(AppModel.self) private var model
    let host: Host
    let result: ScanResult

    var body: some View {
        ScrollView {
            VStack(alignment: .leading, spacing: 20) {
                header
                identity
                findings
                if result.profile.scansPorts { ports }
                cves
                if !host.hostScripts.isEmpty { hostScripts }
            }
            .padding(20)
            .frame(maxWidth: .infinity, alignment: .leading)
        }
        .navigationTitle(host.displayName)
    }

    private var header: some View {
        HStack(alignment: .top, spacing: 14) {
            Image(systemName: host.kind.symbol)
                .font(.system(size: 34))
                .frame(width: 52, height: 52)
                .background(.quaternary, in: RoundedRectangle(cornerRadius: 12))
            VStack(alignment: .leading, spacing: 4) {
                HStack {
                    Text(host.displayName).font(.title2.bold()).textSelection(.enabled)
                    if !model.isTrusted(host) { NewBadge() }
                }
                Text(host.kind.label + (host.isGateway ? " · gateway" : "") + (host.isLocalMachine ? " · this Mac" : ""))
                    .foregroundStyle(.secondary)
            }
            Spacer()
            VStack(alignment: .trailing, spacing: 6) {
                Button(model.isTrusted(host) ? "Known Device ✓" : "Mark as Known") {
                    model.toggleTrusted(host)
                }
                if let web = webURL {
                    Button("Open Web Interface") { NSWorkspace.shared.open(web) }
                }
            }
        }
    }

    private var identity: some View {
        Grid(alignment: .leading, horizontalSpacing: 16, verticalSpacing: 6) {
            row("IP", host.ip, mono: true)
            row("MAC", host.mac ?? "— (needs administrator mode or an ARP entry)", mono: host.mac != nil)
            row("Vendor", host.vendor ?? "—")
            if let m = host.model { row("Model", m) }
            if let s = host.bonjourServices, !s.isEmpty { row("Bonjour services", s.joined(separator: ", ")) }
            if host.hostnames.count > 0 { row("Hostname", host.hostnames.joined(separator: ", ")) }
            if let os = host.bestOSGuess { row("System", "\(os.name) (\(os.accuracy)%)") }
            if let ms = host.latencyMs { row("Latency", String(format: "%.1f ms", ms)) }
        }
        .padding(14)
        .background(.background.secondary, in: RoundedRectangle(cornerRadius: 10))
    }

    private func row(_ label: String, _ value: String, mono: Bool = false) -> some View {
        GridRow {
            Text(label).foregroundStyle(.secondary)
            Text(value)
                .font(mono ? .body.monospaced() : .body)
                .textSelection(.enabled)
        }
    }

    @ViewBuilder
    private var findings: some View {
        let list = result.findings(for: host)
        VStack(alignment: .leading, spacing: 10) {
            Text("Issues found").font(.headline)
            if list.isEmpty {
                Label(result.profile.scansPorts ? "No issues found" : "No audit run (Discovery profile)",
                      systemImage: "checkmark.shield")
                    .foregroundStyle(.secondary)
            }
            ForEach(list) { f in
                VStack(alignment: .leading, spacing: 6) {
                    HStack {
                        SeverityPill(severity: f.severity, text: f.severity.label)
                        Text(f.title).bold()
                        Spacer()
                        if let p = f.port { Text(p).font(.caption.monospaced()).foregroundStyle(.secondary) }
                    }
                    Text(f.detail)
                    Label(f.remediation, systemImage: "wrench.and.screwdriver")
                        .font(.callout)
                        .foregroundStyle(.secondary)
                    if let ev = f.evidence {
                        Text(ev).font(.caption.monospaced()).foregroundStyle(.tertiary).textSelection(.enabled)
                    }
                }
                .padding(12)
                .frame(maxWidth: .infinity, alignment: .leading)
                .background(f.severity.color.opacity(0.08), in: RoundedRectangle(cornerRadius: 10))
                .overlay(alignment: .leading) {
                    UnevenRoundedRectangle(topLeadingRadius: 10, bottomLeadingRadius: 10)
                        .fill(f.severity.color)
                        .frame(width: 4)
                }
            }
        }
    }

    private var ports: some View {
        VStack(alignment: .leading, spacing: 10) {
            Text("Open ports (\(host.openPorts.count))").font(.headline)
            if host.openPorts.isEmpty {
                Text("No open ports among those scanned.").foregroundStyle(.secondary)
            }
            ForEach(host.openPorts) { p in
                DisclosureGroup {
                    VStack(alignment: .leading, spacing: 8) {
                        ForEach(p.scripts, id: \.id) { s in
                            VStack(alignment: .leading, spacing: 2) {
                                Text(s.id).font(.caption.bold())
                                Text(s.output.trimmingCharacters(in: .whitespacesAndNewlines))
                                    .font(.caption.monospaced())
                                    .textSelection(.enabled)
                            }
                        }
                        if p.scripts.isEmpty {
                            Text("No script output.").font(.caption).foregroundStyle(.secondary)
                        }
                    }
                    .frame(maxWidth: .infinity, alignment: .leading)
                    .padding(.leading, 8)
                } label: {
                    HStack {
                        Text(p.id).font(.body.monospaced()).frame(width: 90, alignment: .leading)
                        Text(p.serviceName.isEmpty ? "?" : p.serviceName)
                            .frame(width: 110, alignment: .leading)
                        if p.service?.isTLS == true {
                            Image(systemName: "lock.fill").foregroundStyle(.green).help("Service over TLS")
                        }
                        Text(p.service?.productSummary ?? "").foregroundStyle(.secondary).lineLimit(1)
                    }
                }
            }
        }
    }

    /// CVE note per i servizi di questo dispositivo.
    @ViewBuilder
    private var cves: some View {
        let perPort = host.openPorts.map { ($0, CVEAudit.entries(for: $0, in: result.vulnerabilities)) }.filter { !$1.isEmpty }
        if !perPort.isEmpty {
            VStack(alignment: .leading, spacing: 10) {
                Text("Known vulnerabilities (CVE)").font(.headline)
                Text("Based on the version reported by the service: verify on the device.")
                    .font(.caption).foregroundStyle(.secondary)
                ForEach(perPort, id: \.0.id) { port, entries in
                    DisclosureGroup {
                        VStack(alignment: .leading, spacing: 8) {
                            ForEach(entries) { e in
                                HStack(alignment: .top, spacing: 8) {
                                    SeverityPill(severity: e.subnetScoutSeverity,
                                                 text: e.cvss.map { String(format: "%.1f", $0) } ?? "n/d")
                                        .frame(width: 44, alignment: .leading)
                                    VStack(alignment: .leading, spacing: 2) {
                                        HStack(spacing: 6) {
                                            Link(e.id, destination: e.url).font(.callout.monospaced())
                                            if e.knownExploited {
                                                Text("ACTIVELY EXPLOITED")
                                                    .font(.system(size: 9, weight: .heavy))
                                                    .padding(.horizontal, 4).padding(.vertical, 1)
                                                    .foregroundStyle(.white).background(.red, in: Capsule())
                                                    .help(e.kevName ?? "In the CISA KEV catalog")
                                            }
                                            if let d = e.published { Text(d).font(.caption).foregroundStyle(.tertiary) }
                                        }
                                        Text(e.summary).font(.caption).foregroundStyle(.secondary).lineLimit(3)
                                    }
                                }
                            }
                        }
                        .padding(.leading, 8)
                    } label: {
                        HStack {
                            Text(port.id).font(.body.monospaced())
                            Text(port.service?.productSummary ?? "").foregroundStyle(.secondary)
                            Spacer()
                            Text("\(entries.count) CVE").foregroundStyle(.secondary)
                        }
                    }
                }
            }
        } else if let error = result.cveError {
            Label("CVE lookup not completed: \(error)", systemImage: "exclamationmark.triangle")
                .font(.caption).foregroundStyle(.orange)
        }
    }

    private var hostScripts: some View {
        VStack(alignment: .leading, spacing: 8) {
            Text("Host-level scripts").font(.headline)
            ForEach(host.hostScripts, id: \.id) { s in
                VStack(alignment: .leading, spacing: 2) {
                    Text(s.id).font(.caption.bold())
                    Text(s.output.trimmingCharacters(in: .whitespacesAndNewlines))
                        .font(.caption.monospaced())
                        .textSelection(.enabled)
                }
            }
        }
    }

    private var webURL: URL? {
        let open = host.openPorts.filter { $0.proto == "tcp" }
        if let https = open.first(where: { $0.service?.isTLS == true && ($0.serviceName.contains("http") || $0.number == 443) }) {
            return URL(string: "https://\(host.ip):\(https.number)")
        }
        if let http = open.first(where: { $0.serviceName.hasPrefix("http") }) {
            return URL(string: "http://\(host.ip):\(http.number)")
        }
        return nil
    }
}
