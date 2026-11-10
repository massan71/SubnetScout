import SwiftUI
import AppKit
import ScanKit

/// Visual check mode:
///
///     SubnetScout.app/Contents/MacOS/SubnetScout --qa-snapshots /path/to/folder
///
/// Opens the main views in off-screen windows with the real history data
/// and saves a PNG of each. Used to check the interface without clicking.
@MainActor
enum QASnapshots {
    static func runIfRequested() -> Bool {
        let args = CommandLine.arguments
        guard let i = args.firstIndex(of: "--qa-snapshots"), i + 1 < args.count else { return false }
        let dir = URL(fileURLWithPath: args[i + 1], isDirectory: true)
        try? FileManager.default.createDirectory(at: dir, withIntermediateDirectories: true)
        _ = NSApplication.shared
        NSApp.setActivationPolicy(.accessory)
        Task { @MainActor in
            await capture(into: dir)
            exit(0)
        }
        NSApp.run()
        return true
    }

    static func capture(into dir: URL) async {
        let model = AppModel()
        await model.refreshHelper()
        try? await Task.sleep(for: .milliseconds(300))

        // The device with the most issues, to fill the detail view.
        let worst = model.current.flatMap { r in
            r.hosts.max { r.findings(for: $0).count < r.findings(for: $1).count }
        }
        let withCVE = model.history.lazy.compactMap { r -> (ScanResult, Host)? in
            guard let v = r.vulnerabilities,
                  let h = r.hosts.first(where: { $0.openPorts.contains { !CVEAudit.entries(for: $0, in: v).isEmpty } })
            else { return nil }
            return (r, h)
        }.first

        func main(_ name: String, prepare: () -> Void) async {
            prepare()
            await snap(ContentView().environment(model), size: CGSize(width: 1400, height: 860), name: name, dir: dir)
        }

        await main("01-devices") { model.resultsMode = .devices; model.selectedHostID = worst?.id }
        await main("02-issues") { model.resultsMode = .findings }
        await main("03-network") { model.resultsMode = .network }
        await main("03b-map") { model.resultsMode = .map; model.selectedHostID = worst?.id }
        if let (scan, host) = withCVE {
            await main("04-cve") { model.show(scan); model.resultsMode = .devices; model.selectedHostID = host.id }
        }
        await snap(ScheduleSettingsView().environment(model).frame(width: 540), size: CGSize(width: 540, height: 640),
                   name: "05-settings-schedule", dir: dir)
        await snap(CVESettingsView().frame(width: 540), size: CGSize(width: 540, height: 520),
                   name: "06-settings-cve", dir: dir)
        await snap(VStack(alignment: .leading, spacing: 6) { MenuBarContent().environment(model) }
                    .buttonStyle(.borderless).padding(12).frame(width: 320, alignment: .leading),
                   size: CGSize(width: 320, height: 260), name: "07-menu", dir: dir)
        await snap(OnboardingView(onDone: {}).environment(model), size: CGSize(width: 620, height: 560),
                   name: "08-onboarding", dir: dir)
    }

    static func snap<V: View>(_ view: V, size: CGSize, name: String, dir: URL) async {
        let host = NSHostingView(rootView: view.background(Color(nsColor: .windowBackgroundColor)))
        host.frame = CGRect(origin: .zero, size: size)
        let window = NSWindow(contentRect: host.frame, styleMask: [.titled, .resizable], backing: .buffered, defer: false)
        window.contentView = host
        window.appearance = NSApp.effectiveAppearance
        window.backgroundColor = .windowBackgroundColor
        window.setFrameOrigin(NSPoint(x: -10_000, y: -10_000))
        window.orderFrontRegardless()
        // Give SwiftUI time to lay out (tables and forms are AppKit views).
        for _ in 0..<6 {
            host.layoutSubtreeIfNeeded()
            try? await Task.sleep(for: .milliseconds(200))
        }
        guard let rep = host.bitmapImageRepForCachingDisplay(in: host.bounds) else { return }
        host.cacheDisplay(in: host.bounds, to: rep)
        try? rep.representation(using: .png, properties: [:])?.write(to: dir.appending(path: "\(name).png"))
        window.orderOut(nil)
    }
}
