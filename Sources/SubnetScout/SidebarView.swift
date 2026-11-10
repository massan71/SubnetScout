import SwiftUI
import ScanKit

struct SidebarView: View {
    @Environment(AppModel.self) private var model
    @AppStorage(CVESettings.enabledKey) private var cveEnabled = false

    // Form raggruppato invece di List(.sidebar): le righe si adattano ai testi
    // lunghi (descrizioni, messaggi del helper) invece di troncarli.
    var body: some View {
        @Bindable var model = model
        Form {
                Section("Target") {
                    if !model.interfaces.isEmpty {
                        Menu {
                            ForEach(model.interfaces) { iface in
                                Button(iface.label) { model.target = iface.cidr }
                            }
                        } label: {
                            Label("Local network", systemImage: "network")
                        }
                    }
                    TextField("Target", text: $model.target, prompt: Text("e.g. 192.168.1.0/24"))
                        .labelsHidden()
                        .textFieldStyle(.roundedBorder)
                        .font(.system(.body, design: .monospaced))
                        .onSubmit { model.startScan() }
                    if let current = otherNetworkHint {
                        HStack {
                            Label("Not the current network (\(current)).", systemImage: "wifi.exclamationmark")
                                .font(.caption).foregroundStyle(.orange)
                            Button("Use current network") { model.target = current }
                                .controlSize(.small)
                        }
                    }
                    if let warning = sizeWarning {
                        Label(warning, systemImage: "exclamationmark.triangle")
                            .font(.caption)
                            .foregroundStyle(.orange)
                    }
                }

                Section("Profile") {
                    Picker("Profile", selection: $model.profile) {
                        ForEach(ScanProfile.allCases) { Text($0.name).tag($0) }
                    }
                    .labelsHidden()
                    Text(model.profile.summary)
                        .font(.caption)
                        .foregroundStyle(.secondary)
                    Toggle(isOn: $model.privileged.animation()) {
                        VStack(alignment: .leading, spacing: 2) {
                            Text("As administrator")
                            Text("Adds OS detection, UDP and the DHCP probe.")
                                .font(.caption)
                                .foregroundStyle(.secondary)
                        }
                    }
                    HelperStatusView()
                    Toggle(isOn: $cveEnabled) {
                        VStack(alignment: .leading, spacing: 2) {
                            Text("Look up known vulnerabilities (CVE)")
                            Text("Sends only software names and versions to NVD, never device data. Options in Settings (⌘,).")
                                .font(.caption)
                                .foregroundStyle(.secondary)
                        }
                    }
                    .disabled(!model.profile.scansPorts)
                }

                Section {
                    ScanButton()
                }

                if let result = model.current {
                    Section("Risk") {
                        RiskSummaryView(result: result)
                    }
                }

                if model.historyLoading && model.history.isEmpty {
                    Section("History") {
                        HStack(spacing: 8) {
                            ProgressView().controlSize(.small)
                            Text("Loading the encrypted history… If macOS asks for Keychain access, choose “Always Allow”.")
                                .font(.caption).foregroundStyle(.secondary)
                        }
                    }
                }
                if !model.history.isEmpty {
                    Section("History") {
                        if let warning = model.historyWarning {
                            Label(warning, systemImage: "lock.trianglebadge.exclamationmark")
                                .font(.caption).foregroundStyle(.orange)
                        }
                        VStack(spacing: 2) {
                            ForEach(model.history) { scan in
                                Button { model.show(scan) } label: {
                                    HistoryRow(scan: scan)
                                        .frame(maxWidth: .infinity, alignment: .leading)
                                        .padding(.horizontal, 6)
                                        .padding(.vertical, 4)
                                        .contentShape(Rectangle())
                                        .background(model.selectedHistoryID == scan.id ? Color.accentColor.opacity(0.2) : .clear,
                                                    in: RoundedRectangle(cornerRadius: 6))
                                }
                                .buttonStyle(.plain)
                                .contextMenu {
                                    Button("Delete", role: .destructive) { model.deleteScan(scan.id) }
                                }
                            }
                        }
                    }
                }

                Section {
                    Text(footer)
                        .font(.caption2)
                        .foregroundStyle(.tertiary)
                }
        }
        .formStyle(.grouped)
    }

    /// Il target è una rete CIDR che non corrisponde a nessuna interfaccia attiva
    /// (tipico dopo aver cambiato Wi-Fi): restituisce la rete attuale da proporre.
    private var otherNetworkHint: String? {
        let t = model.target.trimmingCharacters(in: .whitespaces)
        guard t.contains("/"), !t.contains(" "), let first = model.interfaces.first,
              !model.interfaces.contains(where: { $0.cidr == t }) else { return nil }
        return first.cidr
    }

    private var sizeWarning: String? {
        guard let targets = try? TargetParser.parse(model.target) else { return nil }
        let n = TargetParser.estimatedHostCount(targets)
        return n > 1024 ? "\(n.formatted()) addresses: the scan may take a long time." : nil
    }

    private var footer: String {
        if let v = model.nmapVersion, let p = model.nmapPath { return "nmap \(v) · \(p)" }
        return "nmap not found"
    }
}

/// Stato del privileged helper e azioni per installarlo/approvarlo.
struct HelperStatusView: View {
    @Environment(AppModel.self) private var model

    var body: some View {
        VStack(alignment: .leading, spacing: 6) {
            switch model.helperState {
            case .checking:
                HStack(spacing: 6) {
                    ProgressView().controlSize(.small)
                    Text("Checking the helper…").font(.caption).foregroundStyle(.secondary)
                }
            case .unavailable:
                note("key", .secondary,
                     "As administrator you will be asked for your password. The helper is only available when running SubnetScout.app.")
            case .notInstalled:
                note("key", .secondary, "With the helper every scan is more complete (macOS does not limit it) and no password is ever needed.")
                Button("Install Helper…") { model.installHelper() }
                    .disabled(model.helperBusy)
            case .needsApproval:
                note("hand.raised", .orange,
                     "Approve “SubnetScout” in System Settings › General › Login Items & Extensions.")
                Text("If it already shows as approved (this happens after an update), click “Reinstall” and approve it again.")
                    .font(.caption)
                    .foregroundStyle(.secondary)
                HStack {
                    Button("Open Settings") { HelperClient.openApprovalSettings() }
                    Button("Reinstall") { model.installHelper() }
                        .disabled(model.helperBusy)
                }
                .controlSize(.small)
            case .ready(_, nil, _):
                note("checkmark.shield.fill", .green, "Helper active: every scan runs through it, with no password.")
                Button("Uninstall Helper") { model.uninstallHelper() }
                    .buttonStyle(.link)
                    .font(.caption)
                    .disabled(model.helperBusy)
            case .ready(_, _, true):
                note("shippingbox", .blue,
                     "Found /Applications/nmap.app. To run it as root without a password it must be copied to a protected folder (once, with your password).")
                Button("Copy nmap to Protected Location…") { model.adoptNmap() }
                    .disabled(model.helperBusy)
                Text("Until then, your password is requested for every scan.")
                    .font(.caption)
                    .foregroundStyle(.secondary)
            case .ready(_, let problem?, false):
                note("exclamationmark.shield", .orange, "Helper active, but it will not run this nmap as root:")
                Text(problem)
                    .font(.caption)
                    .foregroundStyle(.secondary)
                Text("Install nmap with the package from nmap.org. Until then, your password will be requested.")
                    .font(.caption)
                HStack {
                    Button("Check Again") { Task { await model.refreshHelper() } }
                    Button("Uninstall") { model.uninstallHelper() }
                        .disabled(model.helperBusy)
                }
                .controlSize(.small)
            case .error(let message):
                note("xmark.octagon", .red, message)
                HStack {
                    Button("Reinstall") { model.installHelper() }
                    Button("Check Again") { Task { await model.refreshHelper() } }
                }
                .controlSize(.small)
            }
        }
        .padding(.vertical, 2)
    }

    private func note(_ symbol: String, _ color: Color, _ text: String) -> some View {
        Label {
            Text(text)
        } icon: {
            Image(systemName: symbol).foregroundStyle(color)
        }
        .font(.caption)
    }
}

struct ScanButton: View {
    @Environment(AppModel.self) private var model

    var body: some View {
        if case .scanning(let progress) = model.phase {
            VStack(alignment: .leading, spacing: 6) {
                if let progress {
                    ProgressView(value: progress) {
                        Text("Scanning… \(Int(progress * 100))%")
                            .font(.callout)
                    }
                } else {
                    ProgressView { Text("Scanning (password)…").font(.callout) }
                        .progressViewStyle(.linear)
                }
                // nmap azzera la percentuale a ogni fase (ping, porte, servizi, script):
                // il tempo trascorso rassicura che la scansione sta andando avanti.
                if let start = model.scanStartedAt {
                    TimelineView(.periodic(from: start, by: 1)) { context in
                        Text("Running for \(Duration.seconds(Int(context.date.timeIntervalSince(start))).formatted(.time(pattern: .minuteSecond))) · \(model.scanStage.isEmpty ? model.scanSummary : model.scanStage)")
                            .font(.caption)
                            .foregroundStyle(.secondary)
                            .monospacedDigit()
                    }
                }
                Button("Stop", role: .cancel) { model.cancelScan() }
            }
        } else {
            Button {
                model.startScan()
            } label: {
                Label("Start Scan", systemImage: "dot.radiowaves.left.and.right")
                    .frame(maxWidth: .infinity)
            }
            .controlSize(.large)
            .buttonStyle(.borderedProminent)
            .disabled(model.nmapPath == nil)
        }
    }
}

struct HistoryRow: View {
    let scan: ScanResult

    var body: some View {
        HStack {
            GradeBadge(grade: scan.profile.scansPorts ? scan.risk.grade : "–", size: 26)
            VStack(alignment: .leading, spacing: 2) {
                Text(scan.finishedAt.formatted(date: .abbreviated, time: .shortened))
                Text("\(scan.target) · \(scan.hosts.count) host · \(scan.profile.name)")
                    .font(.caption)
                    .foregroundStyle(.secondary)
                    .lineLimit(1)
            }
        }
    }
}

struct RiskSummaryView: View {
    let result: ScanResult

    var body: some View {
        let risk = result.risk
        HStack(spacing: 12) {
            GradeBadge(grade: result.profile.scansPorts ? risk.grade : "–", size: 44)
            VStack(alignment: .leading, spacing: 4) {
                if !result.profile.scansPorts {
                    // La Discovery non analizza servizi: un voto «A» sarebbe fuorviante.
                    Text("No audit run").font(.headline)
                    Text("Discovery only finds devices: use Quick or Standard for a grade.")
                        .font(.caption).foregroundStyle(.secondary)
                } else {
                Text("Score \(risk.score)/100")
                    .font(.headline)
                HStack(spacing: 6) {
                    ForEach(Severity.allCases.reversed(), id: \.self) { sev in
                        if let n = risk.counts[sev], n > 0 {
                            SeverityPill(severity: sev, text: "\(n)")
                        }
                    }
                    if risk.counts.isEmpty {
                        Text("No issues").font(.caption).foregroundStyle(.secondary)
                    }
                }
                }
            }
        }
        .padding(.vertical, 4)
    }
}
