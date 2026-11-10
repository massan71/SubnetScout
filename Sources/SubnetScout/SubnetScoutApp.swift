import SwiftUI
import AppKit
import UserNotifications

@main
enum Entry {
    static func main() {
        // SubnetScout --diagnose-network: controlla rete locale, ARP, DHCP e UPnP con
        // i permessi e le impostazioni reali dell'app, stampa il risultato ed esce.
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
                Button("Avvia scansione") { model.startScan() }
                    .keyboardShortcut("r", modifiers: .command)
                    .disabled(model.isScanning || model.nmapPath == nil)
                Button("Interrompi scansione") { model.cancelScan() }
                    .keyboardShortcut(".", modifiers: .command)
                    .disabled(!model.isScanning)
                Divider()
                Button("Esporta report HTML…") { model.export(.html) }
                    .keyboardShortcut("e", modifiers: .command)
                    .disabled(model.current == nil)
            }
            CommandGroup(replacing: .help) {
                Button("Configurazione guidata…") { model.showOnboarding = true }
                Link("SubnetScout su GitHub", destination: URL(string: "https://github.com/massan71/SubnetScout")!)
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
        // Necessario quando si avvia con `swift run` (binario senza bundle).
        NSApp.setActivationPolicy(.regular)
        NSApp.activate(ignoringOtherApps: true)
    }

    /// Con l'icona nella barra dei menu l'app resta attiva anche a finestra chiusa,
    /// così le scansioni programmate continuano.
    func applicationShouldTerminateAfterLastWindowClosed(_ sender: NSApplication) -> Bool {
        !ScheduleSettings.showMenuBar
    }

    // Clic su una notifica: apri la scansione.
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
