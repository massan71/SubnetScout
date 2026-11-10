import SwiftUI
import AppKit
import ScanKit

// MARK: - Barra dei menu

struct MenuBarContent: View {
    @Environment(AppModel.self) private var model
    @Environment(\.openWindow) private var openWindow

    var body: some View {
        if case .scanning(let progress) = model.phase {
            Text("Scansione in corso… \(Int((progress ?? 0) * 100))%")
            if !model.scanStage.isEmpty { Text(model.scanStage) }
        } else if let last = model.history.first {
            let risk = last.risk
            Text("Ultima: \(last.finishedAt.formatted(.relative(presentation: .named))) · voto \(risk.grade)")
            Text("\(last.hosts.count) dispositivi · \(last.findings.filter { $0.severity >= .medium }.count) problemi rilevanti")
        } else {
            Text("Nessuna scansione")
        }
        if let next = model.scheduler?.nextRun {
            Text("Prossima: \(next.formatted(.relative(presentation: .named)))")
        }
        if let skip = model.scheduler?.lastSkipReason {
            Text("⚠︎ \(skip)")
        }

        Divider()
        Button(model.isScanning ? "Interrompi scansione" : "Scansiona ora") {
            if model.isScanning { model.cancelScan() } else { model.startScan() }
        }
        .disabled(model.nmapPath == nil)
        Button("Apri SubnetScout") {
            openWindow(id: "main")
            NSApp.activate(ignoringOtherApps: true)
        }
        SettingsLink { Text("Impostazioni…") }
        Divider()
        Button("Esci da SubnetScout") { NSApp.terminate(nil) }
            .keyboardShortcut("q")
    }
}

// MARK: - Impostazioni

struct SettingsTabs: View {
    var body: some View {
        TabView {
            ScheduleSettingsView()
                .tabItem { Label("Pianificazione", systemImage: "clock") }
            CVESettingsView()
                .tabItem { Label("Vulnerabilità", systemImage: "shield.lefthalf.filled") }
        }
        .frame(width: 540)
    }
}

struct ScheduleSettingsView: View {
    @Environment(AppModel.self) private var model
    @AppStorage(ScheduleSettings.enabledKey) private var enabled = false
    @AppStorage(ScheduleSettings.intervalKey) private var interval = ScheduleSettings.Interval.daily.rawValue
    @AppStorage(ScheduleSettings.profileKey) private var profile = ScanProfile.quick.rawValue
    @AppStorage(ScheduleSettings.targetKey) private var target = ""
    @AppStorage(ScheduleSettings.fullPrivilegesKey) private var fullPrivileges = false
    @AppStorage(ScheduleSettings.notifyKey) private var notify = true
    @AppStorage(ScheduleSettings.menuBarKey) private var showMenuBar = true
    @State private var launchAtLogin = LoginItem.isEnabled
    @State private var loginError: String?

    var body: some View {
        Form {
            Section("Scansione programmata") {
                Toggle("Scansiona la rete automaticamente", isOn: $enabled)
                Picker("Frequenza", selection: $interval) {
                    ForEach(ScheduleSettings.Interval.allCases) { Text($0.label).tag($0.rawValue) }
                }
                Picker("Profilo", selection: $profile) {
                    ForEach(ScanProfile.allCases.filter { $0 != .full }) { Text($0.name).tag($0.rawValue) }
                }
                TextField("Target", text: $target, prompt: Text("Rete attuale (automatica)"))
                    .font(.body.monospaced())
                Toggle("Come amministratore (OS, UDP, sonda DHCP)", isOn: $fullPrivileges)
                Text(statusText)
                    .font(.caption)
                    .foregroundStyle(.secondary)
            }

            Section("Notifiche") {
                Toggle("Avvisami quando cambia qualcosa", isOn: $notify)
                Button("Invia notifica di prova") { Notifier.postTest() }
                Text("Nuovi dispositivi non segnati come noti, porte aperte, nuovi problemi di gravità media o superiore, nuove CVE. Le notifiche contengono solo conteggi, mai indirizzi o nomi.")
                    .font(.caption)
                    .foregroundStyle(.secondary)
            }

            Section("Sempre attiva") {
                Toggle("Mostra nella barra dei menu", isOn: $showMenuBar)
                Toggle("Apri all'accesso", isOn: $launchAtLogin)
                    .onChange(of: launchAtLogin) { _, on in
                        do { try LoginItem.set(on); loginError = nil } catch {
                            loginError = error.localizedDescription
                            launchAtLogin = LoginItem.isEnabled
                        }
                    }
                if let loginError { Text(loginError).font(.caption).foregroundStyle(.red) }
                Text("Le scansioni programmate partono solo mentre SubnetScout è aperta: con l'icona nella barra dei menu resta attiva anche chiudendo la finestra.")
                    .font(.caption)
                    .foregroundStyle(.secondary)
            }
        }
        .formStyle(.grouped)
        .onChange(of: enabled) { model.scheduler.settingsChanged() }
        .onChange(of: interval) { model.scheduler.settingsChanged() }
    }

    private var statusText: String {
        guard enabled else { return "Disattivata." }
        var parts: [String] = []
        if let next = model.scheduler?.nextRun {
            parts.append("Prossima scansione \(next.formatted(.relative(presentation: .named))).")
        }
        if !model.usesHelper {
            parts.append("Senza helper le scansioni programmate girano come utente normale e possono essere limitate da macOS.")
        }
        if target.isEmpty {
            parts.append("Con il target automatico vengono saltate le reti più grandi di /22.")
        }
        return parts.joined(separator: " ")
    }
}
