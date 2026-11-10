import Foundation

/// Exportable reports: self-contained HTML (printable to PDF from the browser) and CSV.
public enum ReportGenerator {

    // MARK: - HTML

    public static func html(for r: ScanResult, diff: ScanDiff? = nil, trusted: Set<String> = [],
                            title: String = "Network security report") -> String {
        let risk = r.risk
        let dateStr = r.finishedAt.formatted(date: .long, time: .shortened)
        let duration = Duration.seconds(Int(r.duration)).formatted(.units(allowed: [.hours, .minutes, .seconds], width: .abbreviated))
        let counts = Severity.allCases.reversed().map { sev in
            "<div class=\"count sev-\(sev.rawValue)\"><b>\(risk.counts[sev] ?? 0)</b><span>\(sev.label)</span></div>"
        }.joined()

        var body = """
        <header>
          <div>
            <h1>\(esc(title))</h1>
            <p class="muted">Target <code>\(esc(r.target))</code> · \(esc(dateStr)) · duration \(esc(duration))</p>
          </div>
          <div class="grade grade-\(risk.grade)">\(risk.grade)</div>
        </header>

        <section class="summary">
          <div class="card"><b>\(r.hosts.count)</b><span>active devices</span></div>
          <div class="card"><b>\(r.hosts.reduce(0) { $0 + $1.openPorts.count })</b><span>open ports</span></div>
          <div class="card"><b>\(risk.score)/100</b><span>risk score</span></div>
          <div class="counts">\(counts)</div>
        </section>

        <section>
          <h2>Summary</h2>
          <p>\(esc(executiveSummary(r)))</p>
        </section>
        """

        if let diff, !diff.isEmpty {
            body += "<section><h2>Changes since the scan of \(esc(diff.previousScanDate.formatted(date: .abbreviated, time: .shortened)))</h2><ul>"
            for h in diff.newHosts {
                body += "<li><span class=\"tag new\">new</span> \(esc(h.displayName)) <code>\(esc(h.ip))</code> \(esc(h.vendor ?? ""))</li>"
            }
            for h in diff.goneHosts {
                body += "<li><span class=\"tag gone\">gone</span> \(esc(h.displayName)) <code>\(esc(h.ip))</code></li>"
            }
            for p in diff.openedPorts {
                body += "<li><span class=\"tag new\">port opened</span> \(esc(p.hostName)) <code>\(esc(p.port))</code> \(esc(p.service))</li>"
            }
            for p in diff.closedPorts {
                body += "<li><span class=\"tag gone\">port closed</span> \(esc(p.hostName)) <code>\(esc(p.port))</code> \(esc(p.service))</li>"
            }
            body += "</ul></section>"
        }

        body += "<section><h2>Network map</h2>\(mapSVG(r))<p class=\"muted\">Devices grouped by type around the gateway. Links are logical, not physical cabling.</p></section>"

        if let net = r.network { body += networkSection(net) }

        // Findings
        body += "<section><h2>Issues found (\(r.findings.count))</h2>"
        if r.findings.isEmpty {
            body += r.profile.scansPorts
                ? "<p class=\"muted\">No audit rule was triggered.</p>"
                : "<p class=\"muted\">The Discovery profile does not scan ports: no audit was run.</p>"
        }
        let byIP = Dictionary(r.hosts.map { ($0.ip, $0) }, uniquingKeysWith: { a, _ in a })
        for f in r.findings {
            let hostLabel = byIP[f.hostIP].map { "\($0.displayName) (\(f.hostIP))" } ?? f.hostIP
            body += """
            <article class="finding sev-\(f.severity.rawValue)">
              <div class="fhead"><span class="pill sev-\(f.severity.rawValue)">\(f.severity.label)</span>
                <h3>\(esc(f.title))</h3>
                <code>\(esc(hostLabel))\(f.port.map { " · " + esc($0) } ?? "")</code></div>
              <p>\(esc(f.detail))</p>
              <p class="fix"><b>Remediation:</b> \(esc(f.remediation))</p>
              \(f.evidence.map { "<pre>\(esc($0))</pre>" } ?? "")
            </article>
            """
        }
        body += "</section>"

        // Known vulnerabilities
        if let vulns = r.vulnerabilities {
            var rows = ""
            for h in r.hosts {
                for p in h.openPorts {
                    for e in CVEAudit.entries(for: p, in: vulns).prefix(15) {
                        rows += "<tr><td>\(esc(h.displayName)) <code>\(esc(h.ip)):\(esc(p.id))</code></td>"
                            + "<td><a href=\"\(esc(e.url.absoluteString))\"><code>\(esc(e.id))</code></a>\(e.knownExploited ? " <span class=\"tag new\">KEV</span>" : "")</td>"
                            + "<td>\(e.cvss.map { String(format: "%.1f", $0) } ?? "n/d")</td>"
                            + "<td>\(esc(String(e.summary.prefix(220))))</td></tr>"
                    }
                }
            }
            body += "<section><h2>Known vulnerabilities (CVE)</h2>"
            body += rows.isEmpty
                ? "<p class=\"muted\">No known CVEs for the detected versions.</p>"
                : "<p class=\"muted\">Source: NVD (NIST). Matched on the version reported by each service: to be verified. KEV = actively exploited according to CISA.</p><table><thead><tr><th>Service</th><th>CVE</th><th>CVSS</th><th>Description</th></tr></thead><tbody>\(rows)</tbody></table>"
            body += "</section>"
        } else if let err = r.cveError {
            body += "<section><h2>Known vulnerabilities (CVE)</h2><p class=\"muted\">Lookup not completed: \(esc(err))</p></section>"
        }

        // Inventory
        body += """
        <section><h2>Device inventory</h2>
        <table><thead><tr><th>Device</th><th>IP</th><th>MAC</th><th>Vendor</th><th>Type</th><th>Open ports</th><th>Risk</th></tr></thead><tbody>
        """
        for h in r.hosts {
            let isNew = !trusted.isEmpty && !trusted.contains(h.deviceKey)
            let portsStr = r.profile.scansPorts
                ? h.openPorts.map { "\($0.number)/\($0.proto)" }.joined(separator: ", ")
                : "—"
            body += """
            <tr><td>\(esc(h.displayName))\(isNew ? " <span class=\"tag new\">new</span>" : "")\(h.isGateway ? " <span class=\"tag\">gateway</span>" : "")</td>
            <td><code>\(esc(h.ip))</code></td><td><code>\(esc(h.mac ?? "—"))</code></td>
            <td>\(esc(h.vendor ?? "—"))</td><td>\(esc(h.kind.label))\(h.model.map { "<br><span class=\"muted\">" + esc($0) + "</span>" } ?? "")</td>
            <td class="ports">\(esc(portsStr.isEmpty ? "none" : portsStr))</td><td>\(risk.score(for: h))</td></tr>
            """
        }
        body += "</tbody></table></section>"

        // Technical appendix
        if r.profile.scansPorts {
            body += "<section class=\"appendix\"><h2>Appendix: services by device</h2>"
            for h in r.hosts where !h.openPorts.isEmpty {
                body += "<h3>\(esc(h.displayName)) <code>\(esc(h.ip))</code>\(h.bestOSGuess.map { " · " + esc($0.name) } ?? "")</h3>"
                body += "<table><thead><tr><th>Port</th><th>Service</th><th>Product / version</th></tr></thead><tbody>"
                for p in h.openPorts {
                    body += "<tr><td><code>\(esc(p.id))</code></td><td>\(esc(p.serviceName))\(p.service?.isTLS == true ? " 🔒" : "")</td><td>\(esc(p.service?.productSummary ?? ""))</td></tr>"
                }
                body += "</tbody></table>"
            }
            body += "</section>"
        }

        body += """
        <footer class="muted">Generated by SubnetScout · profile “\(esc(r.profile.name))”\(r.privileged ? " (administrator)" : "")
        · nmap \(esc(r.nmapVersion ?? "?"))<br><code>\(esc(r.nmapArgs ?? ""))</code></footer>
        """

        return """
        <!doctype html>
        <html lang="en"><head><meta charset="utf-8">
        <meta http-equiv="Content-Security-Policy" content="\(csp)">
        <meta name="referrer" content="no-referrer">
        <meta name="viewport" content="width=device-width, initial-scale=1">
        <title>SubnetScout · \(esc(r.target))</title>
        <style>\(css)</style></head>
        <body><main>\(body)</main></body></html>
        """
    }

    /// Inline SVG of the network map (same geometry as the app's Map tab).
    static func mapSVG(_ r: ScanResult) -> String {
        let map = NetworkMap(result: r)
        let scale = 230.0, size = 1000.0, c = size / 2
        func px(_ x: Double) -> String { String(format: "%.1f", c + x * scale) }
        func py(_ y: Double) -> String { String(format: "%.1f", c - y * scale) }
        func color(_ n: NetworkMap.Node) -> String {
            switch n.severity {
            case .critical?: "var(--s4)"
            case .high?: "var(--s3)"
            case .medium?: "var(--s2)"
            case .low?: "var(--s1)"
            default: r.profile.scansPorts ? "#16a34a" : "var(--s0)"
            }
        }
        var svg = "<svg class=\"map\" viewBox=\"0 0 \(Int(size)) \(Int(size))\" role=\"img\" aria-label=\"Network map\">"
        for n in map.nodes {
            let relevant = (n.severity ?? .info) >= .medium
            svg += "<line x1=\"\(px(0))\" y1=\"\(py(0))\" x2=\"\(px(n.x))\" y2=\"\(py(n.y))\" stroke=\"\(relevant ? color(n) : "var(--line)")\" stroke-width=\"\(relevant ? 2 : 1)\"/>"
        }
        for g in map.groups {
            svg += "<text x=\"\(px(g.labelX))\" y=\"\(py(g.labelY))\" class=\"glabel\">\(esc(g.kind.label)) (\(g.count))</text>"
        }
        func circle(_ n: NetworkMap.Node, radius: Double) -> String {
            let relevant = (n.severity ?? .info) >= .medium
            let label = n.isLocalMachine ? "\(n.label) (this Mac)" : n.label
            var out = "<g><title>\(esc(label)) · \(esc(n.ip)) · \(esc(n.kind.label))</title>"
            out += "<circle cx=\"\(px(n.x))\" cy=\"\(py(n.y))\" r=\"\(radius)\" fill=\"var(--card)\" stroke=\"\(color(n))\" stroke-width=\"4\"/>"
            if relevant || n.isGateway || n.isUPnPGateway {
                out += "<text x=\"\(px(n.x))\" y=\"\(String(format: "%.1f", c - n.y * scale + radius + 16))\" class=\"nlabel\">\(esc(String(label.prefix(28))))</text>"
            }
            return out + "</g>"
        }
        for n in map.nodes { svg += circle(n, radius: 13) }
        if let center = map.center { svg += circle(center, radius: 22) }
        return svg + "</svg>"
    }

    static func networkSection(_ n: NetworkContext) -> String {
        func row(_ k: String, _ v: String) -> String { "<tr><th>\(esc(k))</th><td>\(esc(v))</td></tr>" }
        var rows = ""
        rows += row("Gateway", [n.gatewayIP, n.gatewayMAC].compactMap { $0 }.joined(separator: " · ").nonEmpty ?? "—")
        rows += row("DHCP server", n.dhcpServer ?? "—")
        rows += row("Assigned DNS", n.dnsServers.joined(separator: ", ").nonEmpty ?? "—")
        rows += row("Rogue DHCP check", n.dhcpProbed
                    ? (n.dhcpOffers.isEmpty ? "no answer to the probe (inconclusive)" : n.dhcpOffers.map(\.server).joined(separator: ", "))
                    : "not run (requires administrator and the Standard/Full profile)")
        let upnp = n.upnpGateways.map { gw in
            "\(gw.displayName) (\(gw.ip)): " + (gw.mappings.isEmpty ? "no forwarded ports" : "\(gw.mappings.count) forwarded ports")
        }
        rows += row("UPnP routers", n.upnpError ?? (n.upnpProbed ? (upnp.joined(separator: "; ").nonEmpty ?? "none") : "not checked"))
        var html = "<section><h2>Network</h2><table class=\"kv\"><tbody>\(rows)</tbody></table>"
        let mappings = n.upnpGateways.flatMap { gw in gw.mappings.map { (gw, $0) } }
        if !mappings.isEmpty {
            html += "<h3>Ports open to the Internet (UPnP)</h3><table><thead><tr><th>Router</th><th>External port</th><th>Destination</th><th>Description</th><th>Enabled</th></tr></thead><tbody>"
            for (gw, m) in mappings {
                html += "<tr><td>\(esc(gw.displayName))</td><td><code>\(m.externalPort)/\(esc(m.proto.lowercased()))</code></td><td><code>\(esc(m.internalClient)):\(m.internalPort)</code></td><td>\(esc(m.description))</td><td>\(m.enabled ? "yes" : "no")</td></tr>"
            }
            html += "</tbody></table>"
        }
        return html + "</section>"
    }

    static func executiveSummary(_ r: ScanResult) -> String {
        let risk = r.risk
        let crit = risk.counts[.critical] ?? 0, high = risk.counts[.high] ?? 0, med = risk.counts[.medium] ?? 0
        var s = "\(r.hosts.count) active devices were found on \(r.target). "
        guard r.profile.scansPorts else {
            return s + "This was a discovery-only scan: run the “Standard + audit” profile for a risk assessment."
        }
        if crit + high == 0 && med == 0 {
            s += "No significant issues were found: the network gets grade \(risk.grade)."
        } else {
            s += "The overall grade is \(risk.grade) (score \(risk.score)/100), with \(crit) critical, \(high) high and \(med) medium issues. "
            let top = Dictionary(grouping: r.findings.filter { $0.severity >= .high }, by: \.title)
                .sorted { $0.value.count > $1.value.count }.prefix(3)
                .map { "\($0.key.lowercased()) (\($0.value.count))" }
            if !top.isEmpty { s += "Priorities: \(top.joined(separator: ", "))." }
        }
        return s
    }

    /// The report contains text taken from the network (banners, web titles, CVE descriptions):
    /// it is already sanitized, but the CSP blocks scripts and external resources anyway.
    static let csp = "default-src 'none'; style-src 'unsafe-inline'; img-src data:; base-uri 'none'; form-action 'none'"

    static let css = """
    :root{--bg:#f6f7f9;--card:#fff;--fg:#1c1e21;--muted:#6b7280;--line:#e5e7eb;--code:#f1f3f5;
      --s0:#9ca3af;--s1:#3b82f6;--s2:#eab308;--s3:#f97316;--s4:#dc2626}
    @media (prefers-color-scheme:dark){:root{--bg:#111315;--card:#1b1e21;--fg:#e8eaed;--muted:#9aa0a6;--line:#2c3035;--code:#24282c}}
    *{box-sizing:border-box}body{margin:0;background:var(--bg);color:var(--fg);font:15px/1.5 -apple-system,BlinkMacSystemFont,"Helvetica Neue",sans-serif}
    main{max-width:1040px;margin:0 auto;padding:32px 16px 64px}
    header{display:flex;justify-content:space-between;align-items:center;gap:16px}
    h1{margin:0;font-size:28px}h2{margin:36px 0 12px;font-size:20px}h3{margin:0;font-size:16px}
    .muted{color:var(--muted)}code,pre{font:13px ui-monospace,SFMono-Regular,Menlo,monospace}
    pre{background:var(--code);padding:8px 10px;border-radius:6px;white-space:pre-wrap;margin:8px 0 0}
    .grade{font-size:44px;font-weight:800;color:#fff;width:84px;height:84px;border-radius:18px;display:grid;place-items:center;flex:none}
    .grade-A{background:#16a34a}.grade-B{background:#10b981}.grade-C{background:#eab308}.grade-D{background:#f97316}.grade-F{background:#dc2626}
    .summary{display:flex;flex-wrap:wrap;gap:12px;margin-top:24px}
    .card,.count{background:var(--card);border:1px solid var(--line);border-radius:12px;padding:12px 16px;display:flex;flex-direction:column}
    .card b{font-size:24px}.card span,.count span{color:var(--muted);font-size:13px}
    .counts{display:flex;gap:8px;flex-wrap:wrap}.count b{font-size:20px}
    .count.sev-4 b{color:var(--s4)}.count.sev-3 b{color:var(--s3)}.count.sev-2 b{color:var(--s2)}.count.sev-1 b{color:var(--s1)}
    .finding{background:var(--card);border:1px solid var(--line);border-left:5px solid var(--s0);border-radius:10px;padding:14px 16px;margin:10px 0;break-inside:avoid}
    .finding.sev-1{border-left-color:var(--s1)}.finding.sev-2{border-left-color:var(--s2)}.finding.sev-3{border-left-color:var(--s3)}.finding.sev-4{border-left-color:var(--s4)}
    .finding p{margin:8px 0 0}.fix{color:var(--muted)}
    .fhead{display:flex;flex-wrap:wrap;align-items:center;gap:10px}.fhead code{margin-left:auto;color:var(--muted)}
    .pill{font-size:12px;font-weight:700;color:#fff;padding:2px 8px;border-radius:99px;background:var(--s0)}
    .pill.sev-1{background:var(--s1)}.pill.sev-2{background:var(--s2);color:#222}.pill.sev-3{background:var(--s3)}.pill.sev-4{background:var(--s4)}
    .tag{font-size:11px;font-weight:700;text-transform:uppercase;border:1px solid var(--muted);color:var(--muted);padding:0 5px;border-radius:4px}
    .tag.new{border-color:#f97316;color:#f97316}.tag.gone{border-color:var(--muted)}
    table{width:100%;border-collapse:collapse;background:var(--card);border:1px solid var(--line);border-radius:10px;overflow:hidden;display:block;overflow-x:auto}
    th,td{text-align:left;padding:8px 10px;border-bottom:1px solid var(--line);vertical-align:top}
    th{font-size:12px;text-transform:uppercase;color:var(--muted);background:var(--code)}td.ports{font-size:13px;max-width:260px}
    svg.map{width:100%;max-width:760px;display:block;margin:0 auto;background:var(--card);border:1px solid var(--line);border-radius:12px}
    svg.map text{fill:var(--fg);font:13px -apple-system,BlinkMacSystemFont,sans-serif;text-anchor:middle}
    svg.map .glabel{fill:var(--muted);font-weight:600}
    .appendix h3{margin:22px 0 8px}table.kv th{width:240px;text-transform:none;font-size:14px}footer{margin-top:40px;font-size:12px}
    @media print{body{background:#fff}main{padding:0}.finding,table{border-color:#ccc}h2{break-after:avoid}}
    """

    // MARK: - CSV

    /// One row per open port (or one row per host if it has none).
    public static func csv(for r: ScanResult) -> String {
        var lines = ["ip,hostname,mac,vendor,type,port,service,product,issues"]
        for h in r.hosts {
            let findings = r.findings(for: h)
            let base = [h.ip, h.hostnames.first ?? "", h.mac ?? "", h.vendor ?? "", h.kind.label]
            if h.openPorts.isEmpty {
                lines.append((base + ["", "", "", findings.map(\.title).joined(separator: "; ")]).map(csvField).joined(separator: ","))
            }
            for p in h.openPorts {
                let pf = findings.filter { $0.port == p.id }.map { "[\($0.severity.label)] \($0.title)" }
                lines.append((base + [p.id, p.serviceName, p.service?.productSummary ?? "", pf.joined(separator: "; ")])
                    .map(csvField).joined(separator: ","))
            }
        }
        return lines.joined(separator: "\n") + "\n"
    }

    static func csvField(_ s: String) -> String {
        // Apostrophe prefix against formula injection in Excel/Numbers.
        var v = s
        if let first = v.first, "=+-@".contains(first) { v = "'" + v }
        if v.contains(where: { $0 == "," || $0 == "\"" || $0 == "\n" }) {
            return "\"" + v.replacingOccurrences(of: "\"", with: "\"\"") + "\""
        }
        return v
    }

    static func esc(_ s: String) -> String {
        var out = ""
        out.reserveCapacity(s.count)
        for c in s {
            switch c {
            case "&": out += "&amp;"
            case "<": out += "&lt;"
            case ">": out += "&gt;"
            case "\"": out += "&quot;"
            case "'": out += "&#39;"
            default: out.append(c)
            }
        }
        return out
    }
}
