import Foundation

/// Report esportabili: HTML autonomo (stampabile in PDF dal browser) e CSV.
public enum ReportGenerator {

    // MARK: - HTML

    public static func html(for r: ScanResult, diff: ScanDiff? = nil, trusted: Set<String> = [],
                            title: String = "Report di sicurezza della rete") -> String {
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
            <p class="muted">Target <code>\(esc(r.target))</code> · \(esc(dateStr)) · durata \(esc(duration))</p>
          </div>
          <div class="grade grade-\(risk.grade)">\(risk.grade)</div>
        </header>

        <section class="summary">
          <div class="card"><b>\(r.hosts.count)</b><span>dispositivi attivi</span></div>
          <div class="card"><b>\(r.hosts.reduce(0) { $0 + $1.openPorts.count })</b><span>porte aperte</span></div>
          <div class="card"><b>\(risk.score)/100</b><span>punteggio di rischio</span></div>
          <div class="counts">\(counts)</div>
        </section>

        <section>
          <h2>Sintesi</h2>
          <p>\(esc(executiveSummary(r)))</p>
        </section>
        """

        if let diff, !diff.isEmpty {
            body += "<section><h2>Cambiamenti dalla scansione del \(esc(diff.previousScanDate.formatted(date: .abbreviated, time: .shortened)))</h2><ul>"
            for h in diff.newHosts {
                body += "<li><span class=\"tag new\">nuovo</span> \(esc(h.displayName)) <code>\(esc(h.ip))</code> \(esc(h.vendor ?? ""))</li>"
            }
            for h in diff.goneHosts {
                body += "<li><span class=\"tag gone\">sparito</span> \(esc(h.displayName)) <code>\(esc(h.ip))</code></li>"
            }
            for p in diff.openedPorts {
                body += "<li><span class=\"tag new\">porta aperta</span> \(esc(p.hostName)) <code>\(esc(p.port))</code> \(esc(p.service))</li>"
            }
            for p in diff.closedPorts {
                body += "<li><span class=\"tag gone\">porta chiusa</span> \(esc(p.hostName)) <code>\(esc(p.port))</code> \(esc(p.service))</li>"
            }
            body += "</ul></section>"
        }

        // Problemi
        body += "<section><h2>Problemi rilevati (\(r.findings.count))</h2>"
        if r.findings.isEmpty {
            body += r.profile.scansPorts
                ? "<p class=\"muted\">Nessuna regola di audit è scattata.</p>"
                : "<p class=\"muted\">Il profilo Discovery non analizza le porte: nessun audit eseguito.</p>"
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
              <p class="fix"><b>Rimedio:</b> \(esc(f.remediation))</p>
              \(f.evidence.map { "<pre>\(esc($0))</pre>" } ?? "")
            </article>
            """
        }
        body += "</section>"

        // Inventario
        body += """
        <section><h2>Inventario dispositivi</h2>
        <table><thead><tr><th>Dispositivo</th><th>IP</th><th>MAC</th><th>Produttore</th><th>Tipo</th><th>Porte aperte</th><th>Rischio</th></tr></thead><tbody>
        """
        for h in r.hosts {
            let isNew = !trusted.isEmpty && !trusted.contains(h.deviceKey)
            let portsStr = r.profile.scansPorts
                ? h.openPorts.map { "\($0.number)/\($0.proto)" }.joined(separator: ", ")
                : "—"
            body += """
            <tr><td>\(esc(h.displayName))\(isNew ? " <span class=\"tag new\">nuovo</span>" : "")\(h.isGateway ? " <span class=\"tag\">gateway</span>" : "")</td>
            <td><code>\(esc(h.ip))</code></td><td><code>\(esc(h.mac ?? "—"))</code></td>
            <td>\(esc(h.vendor ?? "—"))</td><td>\(esc(h.kind.label))</td>
            <td class="ports">\(esc(portsStr.isEmpty ? "nessuna" : portsStr))</td><td>\(risk.score(for: h))</td></tr>
            """
        }
        body += "</tbody></table></section>"

        // Appendice tecnica
        if r.profile.scansPorts {
            body += "<section class=\"appendix\"><h2>Appendice: servizi per dispositivo</h2>"
            for h in r.hosts where !h.openPorts.isEmpty {
                body += "<h3>\(esc(h.displayName)) <code>\(esc(h.ip))</code>\(h.bestOSGuess.map { " · " + esc($0.name) } ?? "")</h3>"
                body += "<table><thead><tr><th>Porta</th><th>Servizio</th><th>Prodotto / versione</th></tr></thead><tbody>"
                for p in h.openPorts {
                    body += "<tr><td><code>\(esc(p.id))</code></td><td>\(esc(p.serviceName))\(p.service?.isTLS == true ? " 🔒" : "")</td><td>\(esc(p.service?.productSummary ?? ""))</td></tr>"
                }
                body += "</tbody></table>"
            }
            body += "</section>"
        }

        body += """
        <footer class="muted">Generato da SubnetScout · profilo «\(esc(r.profile.name))»\(r.privileged ? " (amministratore)" : "")
        · nmap \(esc(r.nmapVersion ?? "?"))<br><code>\(esc(r.nmapArgs ?? ""))</code></footer>
        """

        return """
        <!doctype html>
        <html lang="it"><head><meta charset="utf-8">
        <meta name="viewport" content="width=device-width, initial-scale=1">
        <title>SubnetScout · \(esc(r.target))</title>
        <style>\(css)</style></head>
        <body><main>\(body)</main></body></html>
        """
    }

    static func executiveSummary(_ r: ScanResult) -> String {
        let risk = r.risk
        let crit = risk.counts[.critical] ?? 0, high = risk.counts[.high] ?? 0, med = risk.counts[.medium] ?? 0
        var s = "Sono stati individuati \(r.hosts.count) dispositivi attivi su \(r.target). "
        guard r.profile.scansPorts else {
            return s + "La scansione era di sola discovery: per una valutazione dei rischi esegui il profilo «Standard + audit»."
        }
        if crit + high == 0 && med == 0 {
            s += "Non sono emersi problemi rilevanti: la rete ottiene il grado \(risk.grade)."
        } else {
            s += "Il grado complessivo è \(risk.grade) (punteggio \(risk.score)/100), con \(crit) problemi critici, \(high) alti e \(med) medi. "
            let top = Dictionary(grouping: r.findings.filter { $0.severity >= .high }, by: \.title)
                .sorted { $0.value.count > $1.value.count }.prefix(3)
                .map { "\($0.key.lowercased()) (\($0.value.count))" }
            if !top.isEmpty { s += "Priorità: \(top.joined(separator: ", "))." }
        }
        return s
    }

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
    .appendix h3{margin:22px 0 8px}footer{margin-top:40px;font-size:12px}
    @media print{body{background:#fff}main{padding:0}.finding,table{border-color:#ccc}h2{break-after:avoid}}
    """

    // MARK: - CSV

    /// Una riga per porta aperta (o una riga per host se non ne ha).
    public static func csv(for r: ScanResult) -> String {
        var lines = ["ip,hostname,mac,vendor,tipo,porta,servizio,prodotto,problemi"]
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
        // Prefisso con apostrofo contro la formula injection in Excel/Numbers.
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
