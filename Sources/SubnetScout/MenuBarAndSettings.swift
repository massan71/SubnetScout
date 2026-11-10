import SwiftUI
import AppKit
import ScanKit

// MARK: - Menu bar

struct MenuBarContent: View {
    @Environment(AppModel.self) private var model
    @Environment(\.openWindow) private var openWindow

    var body: some View {
        if case .scanning(let progress) = model.phase {
            Text("Scanning… \(Int((progress ?? 0) * 100))%")
            if !model.scanStage.isEmpty { Text(model.scanStage) }
        } else if let last = model.history.first {
            let risk = last.risk
            Text("Last: \(last.finishedAt.formatted(.relative(presentation: .named))) · grade \(risk.grade)")
            Text("\(last.hosts.count) devices · \(last.findings.filter { $0.severity >= .medium }.count) relevant issues")
        } else {
            Text("No scans yet")
        }
        if let next = model.scheduler?.nextRun {
            Text("Next: \(next.formatted(.relative(presentation: .named)))")
        }
        if let skip = model.scheduler?.lastSkipReason {
            Text("⚠︎ \(skip)")
        }

        Divider()
        Button(model.isScanning ? "Stop Scan" : "Scan Now") {
            if model.isScanning { model.cancelScan() } else { model.startScan() }
        }
        .disabled(model.nmapPath == nil)
        Button("Open SubnetScout") {
            openWindow(id: "main")
            NSApp.activate(ignoringOtherApps: true)
        }
        SettingsLink { Text("Settings…") }
        Divider()
        Button("Quit SubnetScout") { NSApp.terminate(nil) }
            .keyboardShortcut("q")
    }
}

// MARK: - Settings

struct SettingsTabs: View {
    var body: some View {
        TabView {
            ScheduleSettingsView()
                .tabItem { Label("Schedule", systemImage: "clock") }
            CVESettingsView()
                .tabItem { Label("Vulnerabilities", systemImage: "shield.lefthalf.filled") }
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
            Section("Scheduled scan") {
                Toggle("Scan the network automatically", isOn: $enabled)
                Picker("Frequency", selection: $interval) {
                    ForEach(ScheduleSettings.Interval.allCases) { Text($0.label).tag($0.rawValue) }
                }
                Picker("Profile", selection: $profile) {
                    ForEach(ScanProfile.allCases.filter { $0 != .full }) { Text($0.name).tag($0.rawValue) }
                }
                LabeledContent("Target") {
                    TextField("Target", text: $target, prompt: Text("Current network (automatic)"))
                        .labelsHidden()
                        .multilineTextAlignment(.trailing)
                        .font(.body.monospaced())
                }
                Toggle("As administrator (OS, UDP, DHCP probe)", isOn: $fullPrivileges)
                Text(statusText)
                    .font(.caption)
                    .foregroundStyle(.secondary)
            }

            Section("Notifications") {
                Toggle("Notify me when something changes", isOn: $notify)
                Button("Send Test Notification") { Notifier.postTest() }
                Text("New devices not marked as known, opened ports, new issues of medium severity or higher, new CVEs. Notifications contain only counts, never addresses or names.")
                    .font(.caption)
                    .foregroundStyle(.secondary)
            }

            Section("Always on") {
                Toggle("Show in menu bar", isOn: $showMenuBar)
                Toggle("Open at login", isOn: $launchAtLogin)
                    .onChange(of: launchAtLogin) { _, on in
                        do { try LoginItem.set(on); loginError = nil } catch {
                            loginError = error.localizedDescription
                            launchAtLogin = LoginItem.isEnabled
                        }
                    }
                if let loginError { Text(loginError).font(.caption).foregroundStyle(.red) }
                Text("Scheduled scans only run while SubnetScout is open: with the menu bar icon it keeps running even when you close the window.")
                    .font(.caption)
                    .foregroundStyle(.secondary)
            }
        }
        .formStyle(.grouped)
        .onChange(of: enabled) { model.scheduler.settingsChanged() }
        .onChange(of: interval) { model.scheduler.settingsChanged() }
    }

    private var statusText: String {
        guard enabled else { return "Off." }
        var parts: [String] = []
        if let next = model.scheduler?.nextRun {
            parts.append("Next scan \(next.formatted(.relative(presentation: .named))).")
        }
        if !model.usesHelper {
            parts.append("Without the helper, scheduled scans run as a normal user and may be limited by macOS.")
        }
        if target.isEmpty {
            parts.append("With the automatic target, networks larger than /22 are skipped.")
        }
        return parts.joined(separator: " ")
    }
}
