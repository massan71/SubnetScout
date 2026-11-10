import SwiftUI
import AppKit
import UserNotifications

@main
enum Entry {
    static func main() {
        // SubnetScout --diagnose-network: checks local network, ARP, DHCP and UPnP with
        // the app's real permissions and settings, prints the result and exits.
        if CommandLine.arguments.contains("--diagnose-network") {
            Diagnostics.runAndExit()
        }
        if MainActor.assumeIsolated({ QASnapshots.runIfRequested() }) { return }
        SubnetScoutApp.main()
    }
}

struct SubnetScoutApp: App {
    @NSApplicationDelegateAdaptor(AppDelegate.self) private var appDelegate
    @State private var model = AppModel()

    @AppStorage(ScheduleSettings.menuBarKey) private var showMenuBar = true

    var body: some Scene {
        WindowGroup("SubnetScout", id: "main") {
            ContentView()
                .environment(model)
                .frame(minWidth: 1000, minHeight: 620)
        }
        .commands {
            CommandGroup(after: .newItem) {
                Button("Start Scan") { model.startScan() }
                    .keyboardShortcut("r", modifiers: .command)
                    .disabled(model.isScanning || model.nmapPath == nil)
                Button("Stop Scan") { model.cancelScan() }
                    .keyboardShortcut(".", modifiers: .command)
                    .disabled(!model.isScanning)
                Divider()
                Button("Export HTML Report…") { model.export(.html) }
                    .keyboardShortcut("e", modifiers: .command)
                    .disabled(model.current == nil)
            }
            CommandGroup(replacing: .help) {
                Button("Setup Assistant…") { model.showOnboarding = true }
                Link("SubnetScout on GitHub", destination: URL(string: "https://github.com/massan71/SubnetScout")!)
            }
        }
        MenuBarExtra(isInserted: $showMenuBar) {
            MenuBarContent()
                .environment(model)
        } label: {
            Image(systemName: model.isScanning ? "dot.radiowaves.left.and.right" : "dot.radiowaves.up.forward")
        }
        Settings {
            SettingsTabs()
                .environment(model)
        }
    }
}

final class AppDelegate: NSObject, NSApplicationDelegate, UNUserNotificationCenterDelegate {
    func applicationDidFinishLaunching(_ notification: Notification) {
        UNUserNotificationCenter.current().delegate = self
        // Needed when launched with `swift run` (binary without a bundle).
        NSApp.setActivationPolicy(.regular)
        NSApp.activate(ignoringOtherApps: true)
    }

    /// With the menu bar icon the app stays running even with the window closed,
    /// so scheduled scans keep going.
    func applicationShouldTerminateAfterLastWindowClosed(_ sender: NSApplication) -> Bool {
        !ScheduleSettings.showMenuBar
    }

    // Click on a notification: open the scan.
    nonisolated func userNotificationCenter(_ center: UNUserNotificationCenter, didReceive response: UNNotificationResponse,
                                            withCompletionHandler completionHandler: @escaping () -> Void) {
        let id = (response.notification.request.content.userInfo[Notifier.scanIDKey] as? String).flatMap(UUID.init)
        DispatchQueue.main.async {
            NSApp.activate(ignoringOtherApps: true)
            if let id { NotificationCenter.default.post(name: AppModel.openScanNotification, object: id) }
        }
        completionHandler()
    }

    nonisolated func userNotificationCenter(_ center: UNUserNotificationCenter, willPresent notification: UNNotification,
                                            withCompletionHandler completionHandler: @escaping (UNNotificationPresentationOptions) -> Void) {
        completionHandler([.banner, .list])
    }
}
