import SwiftUI
import AppKit
import ScanKit

/// Setup assistant on first launch (can be reopened from Help › Setup Assistant…).
struct OnboardingView: View {
    @Environment(AppModel.self) private var model
    let onDone: () -> Void

    @State private var step = 0
    @AppStorage(CVESettings.enabledKey) private var cveEnabled = false
    @AppStorage(ScheduleSettings.enabledKey) private var scheduleEnabled = false
    @AppStorage(ScheduleSettings.notifyKey) private var notify = true
    @AppStorage(ScheduleSettings.menuBarKey) private var showMenuBar = true

    private let titles = ["Welcome", "nmap", "Helper", "Options", "Ready"]

    var body: some View {
        VStack(spacing: 0) {
            HStack(spacing: 6) {
                ForEach(titles.indices, id: \.self) { i in
                    Capsule()
                        .fill(i <= step ? Color.accentColor : Color.secondary.opacity(0.25))
                        .frame(height: 4)
                }
            }
            .padding(.horizontal, 28)
            .padding(.top, 22)

            Group {
                switch step {
                case 0: welcome
                case 1: nmapStep
                case 2: helperStep
                case 3: optionsStep
                default: doneStep
                }
            }
            .frame(maxWidth: .infinity, maxHeight: .infinity, alignment: .topLeading)
            .padding(28)

            Divider()
            HStack {
                if step > 0 { Button("Back") { step -= 1 } }
                Spacer()
                if step == 0 {
                    Button("Accept and Continue") { step += 1 }.keyboardShortcut(.defaultAction)
                } else if step < titles.count - 1 {
                    Button("Next") { step += 1 }.keyboardShortcut(.defaultAction)
                } else {
                    Button("Close") { onDone() }
                    Button("Start First Scan") {
                        onDone()
                        model.startScan()
                    }
                    .keyboardShortcut(.defaultAction)
                    .disabled(model.nmapPath == nil)
                }
            }
            .padding(16)
        }
        .frame(width: 620, height: 560)
        .interactiveDismissDisabled()
    }

    // MARK: Steps

    private var welcome: some View {
        VStack(alignment: .leading, spacing: 14) {
            Label("Welcome to SubnetScout", systemImage: "dot.radiowaves.left.and.right")
                .font(.title.bold())
            Text("SubnetScout finds the devices on your network, checks the services they expose and reports risky configurations and known vulnerabilities.")
            GroupBox {
                VStack(alignment: .leading, spacing: 8) {
                    Label("Use it responsibly", systemImage: "hand.raised.fill").font(.headline)
                    Text("Only scan networks you own or are explicitly authorized to test. In many countries, unauthorized scanning of other people's systems is illegal and may violate your ISP's or employer's terms.")
                    Text("The built-in profiles only use NSE scripts from the “safe” and “default” categories: they never attempt exploits or password logins.")
                        .foregroundStyle(.secondary)
                }
                .frame(maxWidth: .infinity, alignment: .leading)
                .padding(6)
            }
        }
    }

    private var nmapStep: some View {
        VStack(alignment: .leading, spacing: 14) {
            Text("1. nmap").font(.title2.bold())
            Text("SubnetScout uses nmap for scanning. nmap is not bundled with the app because of its license.")
            if let path = model.nmapPath {
                status(ok: true, "nmap \(model.nmapVersion ?? "") found in \(path)")
            } else {
                status(ok: false, "nmap is not installed")
                Text("Install it with Homebrew:").padding(.top, 4)
                HStack {
                    Text("brew install nmap")
                        .font(.body.monospaced())
                        .textSelection(.enabled)
                        .padding(6)
                        .background(.quaternary, in: RoundedRectangle(cornerRadius: 6))
                    Button("Copy") {
                        NSPasteboard.general.clearContents()
                        NSPasteboard.general.setString("brew install nmap", forType: .string)
                    }
                }
                Link("Or download the official package from nmap.org", destination: URL(string: "https://nmap.org/download.html#macosx")!)
                Button("Check Again") { model.refreshEnvironment() }
            }
        }
    }

    private var helperStep: some View {
        VStack(alignment: .leading, spacing: 14) {
            Text("2. Helper (recommended)").font(.title2.bold())
            Text("The helper is a small system component that runs nmap with the privileges it needs. With the helper:")
            VStack(alignment: .leading, spacing: 4) {
                Label("scans never ask for your password", systemImage: "key")
                Label("macOS does not limit local network access, so results are complete", systemImage: "network")
                Label("scheduled scans work", systemImage: "clock")
            }
            .font(.callout)
            Text("It only runs nmap with the app's profiles, and only on private networks.")
                .font(.caption).foregroundStyle(.secondary)
            GroupBox { HelperStatusView().frame(maxWidth: .infinity, alignment: .leading).padding(4) }
            Text("After installation, macOS asks you to approve it in System Settings › General › Login Items & Extensions.")
                .font(.caption).foregroundStyle(.secondary)
        }
        .task { await model.refreshHelper() }
    }

    private var optionsStep: some View {
        VStack(alignment: .leading, spacing: 14) {
            Text("3. Options").font(.title2.bold())
            Toggle(isOn: $cveEnabled) {
                VStack(alignment: .leading, spacing: 2) {
                    Text("Look up known vulnerabilities (CVE)")
                    Text("Sends only the names and versions of the software found to NVD (NIST), never device data.")
                        .font(.caption).foregroundStyle(.secondary)
                }
            }
            Toggle(isOn: $scheduleEnabled) {
                VStack(alignment: .leading, spacing: 2) {
                    Text("Scan the network every day")
                    Text("Change frequency, profile and network in Settings › Schedule.")
                        .font(.caption).foregroundStyle(.secondary)
                }
            }
            .onChange(of: scheduleEnabled) { model.scheduler.settingsChanged() }
            Toggle("Notify me when something changes", isOn: $notify)
                .disabled(!scheduleEnabled)
            Toggle("Show the icon in the menu bar", isOn: $showMenuBar)
        }
    }

    private var doneStep: some View {
        VStack(alignment: .leading, spacing: 14) {
            Text("Ready").font(.title2.bold())
            status(ok: model.nmapPath != nil, model.nmapPath != nil ? "nmap installed" : "nmap missing: go back to step 1")
            status(ok: model.usesHelper, model.usesHelper ? "Helper active" : "Helper not active: without it, scans may ask for your password and be limited by macOS")
            status(ok: true, cveEnabled ? "CVE lookup on" : "CVE lookup off")
            status(ok: true, scheduleEnabled ? "Daily scan on" : "Scheduled scans off")
            Text("You can reopen this setup from Help › Setup Assistant.")
                .font(.caption).foregroundStyle(.secondary)
        }
    }

    private func status(ok: Bool, _ text: String) -> some View {
        Label {
            Text(text).fixedSize(horizontal: false, vertical: true)
        } icon: {
            Image(systemName: ok ? "checkmark.circle.fill" : "exclamationmark.triangle.fill")
                .foregroundStyle(ok ? .green : .orange)
        }
    }
}
