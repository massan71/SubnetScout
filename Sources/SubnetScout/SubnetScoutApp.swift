import SwiftUI
import AppKit

@main
struct SubnetScoutApp: App {
    @NSApplicationDelegateAdaptor(AppDelegate.self) private var appDelegate
    @State private var model = AppModel()

    var body: some Scene {
        WindowGroup("SubnetScout") {
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
        }
    }
}

final class AppDelegate: NSObject, NSApplicationDelegate {
    func applicationDidFinishLaunching(_ notification: Notification) {
        // Necessario quando si avvia con `swift run` (binario senza bundle).
        NSApp.setActivationPolicy(.regular)
        NSApp.activate(ignoringOtherApps: true)
    }

    func applicationShouldTerminateAfterLastWindowClosed(_ sender: NSApplication) -> Bool { true }
}
