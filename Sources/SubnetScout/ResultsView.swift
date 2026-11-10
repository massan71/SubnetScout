import SwiftUI
import ScanKit

struct ResultsView: View {
    @Environment(AppModel.self) private var model
    let result: ScanResult

    enum Mode: String, CaseIterable { case devices = "Dispositivi", findings = "Problemi", network = "Rete" }
    @State private var search = ""
    @State private var onlyIssues = false
    @State private var sortOrder = [KeyPathComparator(\HostRow.ipKey)]

    var body: some View {
        VStack(spacing: 0) {
            header
            if let diff = model.diff, !diff.isEmpty {
                DiffBanner(diff: diff)
            }
            if result.hosts.count > 3,
               result.hosts.filter({ !model.isTrusted($0) }).count * 5 >= result.hosts.count * 4 {
                // Quasi tutto è «NUOVO»: spiega a cosa serve e offri la scorciatoia.
                HStack(spacing: 10) {
                    Image(systemName: "lightbulb").foregroundStyle(.yellow)
                    Text("Segna come noti i dispositivi che riconosci: da quel momento «NUOVO» e le notifiche riguarderanno solo quelli davvero nuovi.")
                        .font(.callout)
                        .lineLimit(2)
                    Spacer()
                    Button("Segna tutti come noti") { model.trustAll() }
                }
                .padding(.horizontal, 12)
                .padding(.vertical, 6)
                .background(.yellow.opacity(0.08))
            }
            Divider()
            switch model.resultsMode {
            case .devices: hostTable
            case .findings: findingsList
            case .network: NetworkPanel(result: result)
            }
        }
        // In caso di contenuto troppo alto si taglia il fondo (la tabella scorre), mai l'intestazione.
        .frame(maxWidth: .infinity, maxHeight: .infinity, alignment: .top)
        .searchable(text: $search, placement: .toolbar, prompt: "Cerca IP, nome, produttore, servizio")
        .navigationTitle(result.target)
        .navigationSubtitle("\(result.hosts.count) dispositivi · \(result.finishedAt.formatted(date: .abbreviated, time: .shortened))")
    }

    private var header: some View {
        @Bindable var model = model
        return HStack {
            Picker("Vista", selection: $model.resultsMode) {
                ForEach(Mode.allCases, id: \.self) { m in
                    Text(m == .findings ? "\(m.rawValue) (\(result.findings.count))" : m.rawValue).tag(m)
                }
            }
            .pickerStyle(.segmented)
            .labelsHidden()
            .fixedSize()
            Spacer()
            if model.resultsMode == .devices {
                Toggle("Solo con problemi", isOn: $onlyIssues)
                    .toggleStyle(.checkbox)
            }
        }
        .padding(.horizontal, 12)
        .padding(.vertical, 8)
    }

    // MARK: Dispositivi

    private var rows: [HostRow] {
        let risk = result.risk
        let issues = Dictionary(grouping: result.findings, by: \.hostIP)
        return result.hosts
            .filter { !onlyIssues || issues[$0.ip]?.contains { $0.severity > .info } == true }
            .filter { matches($0) }
            .map { h in
                HostRow(host: h,
                        score: risk.score(for: h),
                        worst: issues[h.ip]?.map(\.severity).max(),
                        trusted: model.isTrusted(h))
            }
            .sorted(using: sortOrder)
    }

    private func matches(_ h: Host) -> Bool {
        guard !search.isEmpty else { return true }
        let haystack = ([h.ip, h.mac ?? "", h.vendor ?? "", h.kind.label] + h.hostnames
                        + h.openPorts.flatMap { [String($0.number), $0.serviceName, $0.service?.productSummary ?? ""] })
            .joined(separator: " ").lowercased()
        return haystack.contains(search.lowercased())
    }

    private var hostTable: some View {
        @Bindable var model = model
        return Table(rows, selection: $model.selectedHostID, sortOrder: $sortOrder) {
            TableColumn("Dispositivo", value: \.name) { row in
                HStack(spacing: 8) {
                    Image(systemName: row.host.kind.symbol)
                        .frame(width: 20)
                        .foregroundStyle(.secondary)
                    VStack(alignment: .leading, spacing: 1) {
                        HStack(spacing: 4) {
                            Text(row.host.displayName).lineLimit(1)
                            if !row.trusted { NewBadge() }
                        }
                        Text(row.host.kind.label).font(.caption).foregroundStyle(.secondary)
                    }
                }
            }
            .width(min: 150, ideal: 180)
            TableColumn("IP", value: \.ipKey) { row in
                Text(row.host.ip).font(.system(.body, design: .monospaced))
            }
            .width(min: 90, ideal: 96)
            TableColumn("Produttore", value: \.vendor) { row in
                Text(row.vendor.isEmpty ? "—" : row.vendor)
                    .lineLimit(1)
                    .foregroundStyle(row.vendor.isEmpty ? .tertiary : .primary)
            }
            .width(min: 70, ideal: 120)
            TableColumn("Porte", value: \.openCount) { row in
                Text(result.profile.scansPorts ? "\(row.openCount)" : "—")
                    .monospacedDigit()
            }
            .width(44)
            TableColumn("Rischio", value: \.score) { row in
                if let worst = row.worst, worst > .info {
                    SeverityPill(severity: worst, text: "\(row.score)")
                } else {
                    Text("OK").font(.caption).foregroundStyle(.secondary)
                }
            }
            .width(min: 66, ideal: 70)
        }
        .contextMenu(forSelectionType: Host.ID.self) { ids in
            if let id = ids.first, let host = result.hosts.first(where: { $0.id == id }) {
                Button(model.isTrusted(host) ? "Rimuovi dai dispositivi noti" : "Segna come noto") {
                    model.toggleTrusted(host)
                }
                Button("Copia IP") { copy(host.ip) }
                if let mac = host.mac { Button("Copia MAC") { copy(mac) } }
            }
            Divider()
            Button("Segna tutti come noti") { model.trustAll() }
        }
    }

    // MARK: Problemi

    private var findingsList: some View {
        @Bindable var model = model
        let filtered = result.findings.filter { f in
            search.isEmpty || "\(f.title) \(f.hostIP) \(f.port ?? "")".lowercased().contains(search.lowercased())
        }
        return Group {
            if filtered.isEmpty {
                ContentUnavailableView(result.profile.scansPorts ? "Nessun problema rilevato" : "Nessun audit",
                                       systemImage: "checkmark.shield",
                                       description: Text(result.profile.scansPorts
                                                         ? "Nessuna regola di audit è scattata."
                                                         : "Il profilo Discovery non analizza le porte: usa «Standard + audit»."))
            } else {
                List(filtered, selection: Binding(
                    get: { nil as Finding.ID? },
                    set: { id in
                        if let id, let f = filtered.first(where: { $0.id == id }) { model.selectedHostID = f.hostIP }
                    })) { f in
                    FindingRow(finding: f, hostName: result.hosts.first { $0.ip == f.hostIP }?.displayName)
                        .tag(f.id)
                }
            }
        }
    }

    private func copy(_ s: String) {
        NSPasteboard.general.clearContents()
        NSPasteboard.general.setString(s, forType: .string)
    }
}

struct HostRow: Identifiable {
    let host: Host
    let score: Int
    let worst: Severity?
    let trusted: Bool

    var id: String { host.id }
    var name: String { host.displayName }
    var ipKey: UInt32 { host.ipSortKey }
    var vendor: String { host.vendor ?? "" }
    var openCount: Int { host.openPorts.count }
}

struct DiffBanner: View {
    let diff: ScanDiff

    var body: some View {
        HStack(spacing: 14) {
            Image(systemName: "arrow.triangle.2.circlepath")
                .foregroundStyle(.blue)
            Text("Rispetto al \(diff.previousScanDate.formatted(date: .abbreviated, time: .shortened)):")
                .foregroundStyle(.secondary)
            item(diff.newHosts.count, "nuovo dispositivo", "nuovi dispositivi", .orange)
            item(diff.goneHosts.count, "sparito", "spariti", .secondary)
            item(diff.openedPorts.count, "porta aperta", "porte aperte", .orange)
            item(diff.closedPorts.count, "porta chiusa", "porte chiuse", .green)
            item(diff.newFindings.count, "nuovo problema", "nuovi problemi", .red)
            Spacer()
        }
        .font(.callout)
        .padding(.horizontal, 12)
        .padding(.vertical, 6)
        .background(.blue.opacity(0.08))
    }

    @ViewBuilder
    private func item(_ n: Int, _ one: String, _ many: String, _ color: Color) -> some View {
        if n > 0 {
            Text("\(n) \(n == 1 ? one : many)").foregroundStyle(color).bold()
        }
    }

}

struct FindingRow: View {
    let finding: Finding
    var hostName: String?

    var body: some View {
        HStack(alignment: .top, spacing: 10) {
            SeverityPill(severity: finding.severity, text: finding.severity.label)
                .frame(width: 64, alignment: .leading)
            VStack(alignment: .leading, spacing: 3) {
                Text(finding.title).font(.headline)
                Text([hostName.map { "\($0) (\(finding.hostIP))" } ?? finding.hostIP, finding.port]
                        .compactMap { $0 }.joined(separator: " · "))
                    .font(.caption.monospaced())
                    .foregroundStyle(.secondary)
                Text(finding.detail).font(.callout)
            }
        }
        .padding(.vertical, 4)
    }
}
