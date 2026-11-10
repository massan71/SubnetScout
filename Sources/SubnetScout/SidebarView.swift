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
                            Label("Rete locale", systemImage: "network")
                        }
                    }
                    TextField("Target", text: $model.target, prompt: Text("es. 192.168.1.0/24"))
                        .labelsHidden()
                        .textFieldStyle(.roundedBorder)
                        .font(.system(.body, design: .monospaced))
                        .onSubmit { model.startScan() }
                    if let current = otherNetworkHint {
                        HStack {
                            Label("Non è la rete attuale (\(current)).", systemImage: "wifi.exclamationmark")
                                .font(.caption).foregroundStyle(.orange)
                            Button("Usa la rete attuale") { model.target = current }
                                .controlSize(.small)
                        }
                    }
                    if let warning = sizeWarning {
                        Label(warning, systemImage: "exclamationmark.triangle")
                            .font(.caption)
                            .foregroundStyle(.orange)
                    }
                }

                Section("Profilo") {
                    Picker("Profilo", selection: $model.profile) {
                        ForEach(ScanProfile.allCases) { Text($0.name).tag($0) }
                    }
                    .labelsHidden()
                    Text(model.profile.summary)
                        .font(.caption)
                        .foregroundStyle(.secondary)
                    Toggle(isOn: $model.privileged.animation()) {
                        VStack(alignment: .leading, spacing: 2) {
                            Text("Come amministratore")
                            Text("Aggiunge riconoscimento del sistema operativo, UDP e sonda DHCP.")
                                .font(.caption)
                                .foregroundStyle(.secondary)
                        }
                    }
                    HelperStatusView()
                    Toggle(isOn: $cveEnabled) {
                        VStack(alignment: .leading, spacing: 2) {
                            Text("Cerca vulnerabilità note (CVE)")
                            Text("Invia a NVD solo nome e versione dei software, mai dati dei dispositivi. Opzioni in Impostazioni (⌘,).")
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
                    Section("Rischio") {
                        RiskSummaryView(result: result)
                    }
                }

                if model.historyLoading && model.history.isEmpty {
                    Section("Storico") {
                        HStack(spacing: 8) {
                            ProgressView().controlSize(.small)
                            Text("Caricamento dello storico cifrato… Se macOS chiede l'accesso al Portachiavi, scegli «Consenti sempre».")
                                .font(.caption).foregroundStyle(.secondary)
                        }
                    }
                }
                if !model.history.isEmpty {
                    Section("Storico") {
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
                                    Button("Elimina", role: .destructive) { model.deleteScan(scan.id) }
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
        return n > 1024 ? "\(n.formatted()) indirizzi: la scansione può richiedere molto tempo." : nil
    }

    private var footer: String {
        if let v = model.nmapVersion, let p = model.nmapPath { return "nmap \(v) · \(p)" }
        return "nmap non trovato"
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
                    Text("Controllo dell'helper…").font(.caption).foregroundStyle(.secondary)
                }
            case .unavailable:
                note("key", .secondary,
                     "Come amministratore verrà chiesta la password. Il helper è disponibile solo avviando SubnetScout.app.")
            case .notInstalled:
                note("key", .secondary, "Con il helper tutte le scansioni sono più complete (macOS non le limita) e non serve mai la password.")
                Button("Installa helper…") { model.installHelper() }
                    .disabled(model.helperBusy)
            case .needsApproval:
                note("hand.raised", .orange,
                     "Approva «SubnetScout» in Impostazioni di Sistema › Generali › Elementi login ed estensioni.")
                Text("Se risulta già approvato (succede dopo aver ricompilato l'app), premi «Reinstalla» e riapprova.")
                    .font(.caption)
                    .foregroundStyle(.secondary)
                HStack {
                    Button("Apri Impostazioni") { HelperClient.openApprovalSettings() }
                    Button("Reinstalla") { model.installHelper() }
                        .disabled(model.helperBusy)
                }
                .controlSize(.small)
            case .ready(_, nil, _):
                note("checkmark.shield.fill", .green, "Helper attivo: tutte le scansioni passano da lui, senza password.")
                Button("Disinstalla helper") { model.uninstallHelper() }
                    .buttonStyle(.link)
                    .font(.caption)
                    .disabled(model.helperBusy)
            case .ready(_, _, true):
                note("shippingbox", .blue,
                     "Trovato /Applications/nmap.app. Per eseguirlo come root senza password va copiato in una cartella protetta (una sola volta, con la password).")
                Button("Copia nmap in posizione protetta…") { model.adoptNmap() }
                    .disabled(model.helperBusy)
                Text("Fino ad allora la password viene chiesta a ogni scansione.")
                    .font(.caption)
                    .foregroundStyle(.secondary)
            case .ready(_, let problem?, false):
                note("exclamationmark.shield", .orange, "Helper attivo, ma non userà questo nmap come root:")
                Text(problem)
                    .font(.caption)
                    .foregroundStyle(.secondary)
                Text("Installa nmap dal pacchetto di nmap.org. Fino ad allora verrà chiesta la password.")
                    .font(.caption)
                HStack {
                    Button("Ricontrolla") { Task { await model.refreshHelper() } }
                    Button("Disinstalla") { model.uninstallHelper() }
                        .disabled(model.helperBusy)
                }
                .controlSize(.small)
            case .error(let message):
                note("xmark.octagon", .red, message)
                HStack {
                    Button("Reinstalla") { model.installHelper() }
                    Button("Ricontrolla") { Task { await model.refreshHelper() } }
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
                        Text("Scansione in corso… \(Int(progress * 100))%")
                            .font(.callout)
                    }
                } else {
                    ProgressView { Text("Scansione in corso (password)…").font(.callout) }
                        .progressViewStyle(.linear)
                }
                // nmap azzera la percentuale a ogni fase (ping, porte, servizi, script):
                // il tempo trascorso rassicura che la scansione sta andando avanti.
                if let start = model.scanStartedAt {
                    TimelineView(.periodic(from: start, by: 1)) { context in
                        Text("In corso da \(Duration.seconds(Int(context.date.timeIntervalSince(start))).formatted(.time(pattern: .minuteSecond))) · \(model.scanStage.isEmpty ? model.scanSummary : model.scanStage)")
                            .font(.caption)
                            .foregroundStyle(.secondary)
                            .monospacedDigit()
                    }
                }
                Button("Interrompi", role: .cancel) { model.cancelScan() }
            }
        } else {
            Button {
                model.startScan()
            } label: {
                Label("Avvia scansione", systemImage: "dot.radiowaves.left.and.right")
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
                    Text("Audit non eseguito").font(.headline)
                    Text("La Discovery trova solo i dispositivi: per il voto usa Veloce o Standard.")
                        .font(.caption).foregroundStyle(.secondary)
                } else {
                Text("Punteggio \(risk.score)/100")
                    .font(.headline)
                HStack(spacing: 6) {
                    ForEach(Severity.allCases.reversed(), id: \.self) { sev in
                        if let n = risk.counts[sev], n > 0 {
                            SeverityPill(severity: sev, text: "\(n)")
                        }
                    }
                    if risk.counts.isEmpty {
                        Text("Nessun problema").font(.caption).foregroundStyle(.secondary)
                    }
                }
                }
            }
        }
        .padding(.vertical, 4)
    }
}
