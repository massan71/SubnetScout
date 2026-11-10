import SwiftUI
import AppKit
import UniformTypeIdentifiers
import ScanKit

@MainActor
@Observable
final class AppModel {
    enum Phase: Equatable {
        case idle
        case scanning(progress: Double?)
        case failed(String)
    }

    enum ExportFormat { case html, csv, json }

    // Environment
    private(set) var nmapPath: String?
    private(set) var nmapVersion: String?
    private(set) var interfaces: [LocalInterface] = []

    // Configuration
    var target: String = ""
    var profile: ScanProfile = .standard
    var privileged = false

    // State
    private(set) var phase: Phase = .idle
    private(set) var scanStartedAt: Date?
    /// e.g. "Standard + audit · helper"
    private(set) var scanSummary = ""
    /// Phase after nmap, e.g. "CVE lookup 3 of 12".
    private(set) var scanStage = ""
    private(set) var current: ScanResult?
    private(set) var diff: ScanDiff?
    private(set) var history: [ScanResult] = []
    /// History loading (reading the key from the Keychain).
    private(set) var historyLoading = false
    /// History warning (e.g. encrypted scans that cannot be decrypted).
    private(set) var historyWarning: String?
    var selectedHostID: Host.ID?
    /// Shows the setup assistant (Help menu).
    var showOnboarding = false
    /// Results tab (Devices / Issues / Network / Map).
    var resultsMode: ResultsView.Mode = .devices
    var selectedHistoryID: ScanResult.ID?

    /// Devices the user marked as known (key = MAC or IP).
    private(set) var trusted: Set<String>

    /// Privileged helper state.
    private(set) var helperState: HelperState = .checking
    private(set) var helperBusy = false

    private let store = ScanHistoryStore()
    private var scanTask: Task<Void, Never>?
    @ObservationIgnored private var activationObserver: NSObjectProtocol?
    @ObservationIgnored private var openScanObserver: NSObjectProtocol?
    /// Scheduled scans.
    private(set) var scheduler: ScanScheduler!

    /// Internal notification to open a scan (e.g. click on a notification).
    static let openScanNotification = Notification.Name("SubnetScout.openScan")

    init() {
        trusted = Set(UserDefaults.standard.stringArray(forKey: "trustedDevices") ?? [])
        refreshEnvironment()
        // The history is encrypted with a key in the Keychain: reading it can bring up
        // a macOS prompt (after every update, without a Developer ID). It is
        // loaded in the background so the interface is not blocked meanwhile.
        historyLoading = true
        let store = self.store
        Task.detached(priority: .userInitiated) {
            let (all, unreadable) = store.loadAllReportingUnreadable()
            await MainActor.run {
                self.history = all + self.history.filter { s in !all.contains { $0.id == s.id } }
                self.historyLoading = false
                if unreadable > 0 {
                    self.historyWarning = "\(unreadable) saved scans cannot be read: the encryption key in the Keychain is missing, has changed, or access was denied."
                }
                if self.current == nil, let last = self.history.first { self.show(last) }
            }
        }
        Task { await refreshHelper() }
        // After the approval in System Settings the user comes back to the app: check again.
        activationObserver = NotificationCenter.default.addObserver(
            forName: NSApplication.didBecomeActiveNotification, object: nil, queue: .main
        ) { [weak self] _ in
            Task { @MainActor in
                self?.refreshEnvironment()   // the network may have changed (different Wi-Fi)
                await self?.refreshHelper()
            }
        }
        openScanObserver = NotificationCenter.default.addObserver(
            forName: Self.openScanNotification, object: nil, queue: .main
        ) { [weak self] note in
            guard let id = note.object as? UUID else { return }
            Task { @MainActor in self?.open(scanID: id) }
        }
        scheduler = ScanScheduler(model: self)
    }

    // MARK: Privileged helper

    /// The helper is registered and responds (even if nmap cannot be used as root).
    var helperIsReachable: Bool { if case .ready = helperState { true } else { false } }

    /// How the scan will run with "As administrator" on.
    /// With the helper ready every scan goes through it: no password and
    /// no Local Network permission limits. "As administrator" only decides
    /// the arguments (OS detection, UDP, DHCP probe).
    var usesHelper: Bool { helperState.canScan }

    func refreshHelper() async {
        helperState = await HelperClient.currentState()
    }

    func installHelper() {
        helperBusy = true
        Task {
            defer { helperBusy = false }
            do {
                try await HelperClient.install()
                if HelperClient.service.status == .requiresApproval {
                    helperState = .needsApproval
                    HelperClient.openApprovalSettings()
                } else {
                    await refreshHelper()
                }
            } catch {
                helperState = .error("Installation failed: \(error.localizedDescription)")
            }
        }
    }

    func adoptNmap() {
        helperBusy = true
        Task {
            defer { helperBusy = false }
            do {
                _ = try await HelperClient.adoptNmap()
            } catch is AdminAuthorization.Cancelled {
                // the user cancelled the password prompt
            } catch {
                phase = .failed(error.localizedDescription)
            }
            await refreshHelper()
        }
    }

    func uninstallHelper() {
        helperBusy = true
        Task {
            defer { helperBusy = false }
            do {
                try await HelperClient.uninstall()
            } catch {
                phase = .failed("Uninstall failed: \(error.localizedDescription)")
            }
            await refreshHelper()
        }
    }

    var isScanning: Bool { if case .scanning = phase { true } else { false } }

    var selectedHost: Host? {
        guard let id = selectedHostID else { return nil }
        return current?.hosts.first { $0.id == id }
    }

    func refreshEnvironment() {
        nmapPath = NmapLocator.find()
        nmapVersion = nmapPath.flatMap(NmapLocator.version(at:))
        interfaces = NetworkInfo.interfaces()
        if target.isEmpty, let first = interfaces.first { target = first.cidr }
    }

    // MARK: Scan

    enum ScanOrigin { case manual, scheduled }

    func startScan() {
        guard !isScanning else { return }
        do {
            launch(targets: try TargetParser.parse(target), profile: profile, privileged: privileged, origin: .manual)
        } catch {
            phase = .failed(error.localizedDescription)
        }
    }

    /// Starts a scan. Used by the button and by the schedule.
    /// - Returns: false if it did not start (scan already running, nmap missing).
    @discardableResult
    func launch(targets: [String], profile: ScanProfile, privileged: Bool, origin: ScanOrigin) -> Bool {
        guard !isScanning, let nmapPath else { return false }
        // Without a default route the Mac is offline: a LAN scan would find 0 devices.
        if origin == .manual, PrivateTargets.allPrivate(targets), NetworkInfo.defaultRoute().gateway == nil {
            phase = .failed("This Mac does not seem to be connected to any network. Connect to Wi-Fi or Ethernet and try again.")
            return false
        }
        let engine = ScanEngine(nmapPath: nmapPath)
        // The helper only scans private networks: public targets go through local nmap.
        let helperForThis = usesHelper && PrivateTargets.allPrivate(targets)
        // Scheduled scans never ask for the password.
        let askPassword = privileged && !helperForThis && origin == .manual
        let executor: any NmapExecutor = helperForThis
            ? HelperNmapExecutor(fullPrivileges: privileged)
            : LocalNmapExecutor(nmapPath: nmapPath, askPassword: askPassword)
        phase = .scanning(progress: 0)
        scanStartedAt = Date()
        scanSummary = profile.name + (helperForThis ? " · helper" : askPassword ? " · password" : " · user")
            + (origin == .scheduled ? " · scheduled" : "")

        // ARP and UPnP: with the helper active it reads them (it is not subject to the
        // Local Network permission, which macOS can deny the app); if that fails, the app reads them.
        let probe: ScanEngine.ProbeProvider? = helperIsReachable ? { @Sendable in
            if let p = try? await HelperClient.networkProbe() { return p }
            return await NetworkProbe.run(source: "app")
        } : nil

        // CVEs from NVD: only if enabled in the settings (sends product and version).
        let cveLookup: NVDClient? = CVESettings.enabled
            ? NVDClient(options: .init(apiKey: CVESettings.apiKey())) : nil
        scanStage = ""

        // Previous scan of the same target: needed by the rules that compare the network.
        let previous = history.filter { $0.target == targets.joined(separator: " ") }.max { $0.finishedAt < $1.finishedAt }
        let trustedNow = trusted
        // Keeps App Nap from slowing down a scan while the window is hidden.
        let activity = ProcessInfo.processInfo.beginActivity(options: [.userInitiated, .idleSystemSleepDisabled],
                                                             reason: "Network scan")

        scanTask = Task {
            defer { ProcessInfo.processInfo.endActivity(activity) }
            do {
                let result = try await engine.scan(
                    targets: targets, profile: profile, executor: executor,
                    previous: previous, probe: probe, cveLookup: cveLookup,
                    onStatus: { status in Task { @MainActor in self.scanStage = status } },
                    onProgress: { p in
                        Task { @MainActor in
                            guard case .scanning = self.phase else { return }
                            self.phase = .scanning(progress: p)
                        }
                    })
                scanStage = ""
                // Off the main thread: the Keychain key may require confirmation.
                let store = self.store
                if case .failure(let error) = await Task.detached(operation: { try store.save(result) }).result {
                    historyWarning = "Scan not saved to history: \(error.localizedDescription)"
                }
                history.insert(result, at: 0)
                if origin == .manual || current == nil || current?.target == result.target { show(result) }
                phase = .idle
                switch origin {
                case .manual:
                    notify(result)
                case .scheduled:
                    let summary = ChangeSummary(previous: previous, current: result, trusted: trustedNow)
                    if ScheduleSettings.notify, !summary.isEmpty { Notifier.post(summary, scanID: result.id) }
                }
            } catch is CancellationError {
                phase = .idle
            } catch {
                // Scheduled scans fail silently (they retry on the next run).
                phase = origin == .manual ? .failed(error.localizedDescription) : .idle
            }
        }
        return true
    }

    /// Opens the given scan (e.g. from a click on a notification).
    func open(scanID: UUID) {
        if let scan = history.first(where: { $0.id == scanID }) { show(scan) }
    }

    func cancelScan() {
        scanTask?.cancel()
        scanTask = nil
    }

    func dismissError() {
        if case .failed = phase { phase = .idle }
    }

    func show(_ result: ScanResult) {
        current = result
        selectedHistoryID = result.id
        diff = store.previous(of: result, in: history).map { ScanDiff(previous: $0, current: result) }
        if let id = selectedHostID, result.hosts.contains(where: { $0.id == id }) { return }
        selectedHostID = nil
    }

    func deleteScan(_ id: ScanResult.ID) {
        store.delete(id)
        history.removeAll { $0.id == id }
        if current?.id == id {
            current = nil
            diff = nil
            if let first = history.first { show(first) }
        }
    }

    // MARK: Trusted devices

    func isTrusted(_ host: Host) -> Bool { trusted.contains(host.deviceKey) }

    func toggleTrusted(_ host: Host) {
        if trusted.contains(host.deviceKey) { trusted.remove(host.deviceKey) } else { trusted.insert(host.deviceKey) }
        UserDefaults.standard.set(Array(trusted).sorted(), forKey: "trustedDevices")
    }

    func trustAll() {
        guard let current else { return }
        trusted.formUnion(current.hosts.map(\.deviceKey))
        UserDefaults.standard.set(Array(trusted).sorted(), forKey: "trustedDevices")
    }

    // MARK: Export

    func export(_ format: ExportFormat) {
        guard let current else { return }
        let panel = NSSavePanel()
        let stamp = current.finishedAt.formatted(.iso8601.year().month().day())
        switch format {
        case .html:
            panel.allowedContentTypes = [.html]
            panel.nameFieldStringValue = "SubnetScout-report-\(stamp).html"
        case .csv:
            panel.allowedContentTypes = [.commaSeparatedText]
            panel.nameFieldStringValue = "SubnetScout-\(stamp).csv"
        case .json:
            panel.allowedContentTypes = [.json]
            panel.nameFieldStringValue = "SubnetScout-\(stamp).json"
        }
        guard panel.runModal() == .OK, let url = panel.url else { return }
        do {
            try data(for: format, result: current).write(to: url, options: .atomic)
            if format == .html { NSWorkspace.shared.open(url) }
        } catch {
            phase = .failed("Export failed: \(error.localizedDescription)")
        }
    }

    /// Opens the report in the browser without asking where to save it.
    func previewReport() {
        guard let current else { return }
        let url = FileManager.default.temporaryDirectory.appending(path: "SubnetScout-report-\(current.id.uuidString.prefix(8)).html")
        do {
            try data(for: .html, result: current).write(to: url, options: .atomic)
            NSWorkspace.shared.open(url)
        } catch {
            phase = .failed(error.localizedDescription)
        }
    }

    private func data(for format: ExportFormat, result: ScanResult) throws -> Data {
        switch format {
        case .html:
            Data(ReportGenerator.html(for: result, diff: diff, trusted: trusted).utf8)
        case .csv:
            Data(ReportGenerator.csv(for: result).utf8)
        case .json:
            try ScanHistoryStore.encoder().encode(result)
        }
    }

    private func notify(_ result: ScanResult) {
        guard !NSApp.isActive else { return }
        NSApp.requestUserAttention(.informationalRequest)
    }
}
