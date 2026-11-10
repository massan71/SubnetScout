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

    // Ambiente
    private(set) var nmapPath: String?
    private(set) var nmapVersion: String?
    private(set) var interfaces: [LocalInterface] = []

    // Configurazione
    var target: String = ""
    var profile: ScanProfile = .standard
    var privileged = false

    // Stato
    private(set) var phase: Phase = .idle
    private(set) var scanStartedAt: Date?
    /// es. "Standard + audit · helper"
    private(set) var scanSummary = ""
    /// Fase dopo nmap, es. «Ricerca CVE 3 di 12».
    private(set) var scanStage = ""
    private(set) var current: ScanResult?
    private(set) var diff: ScanDiff?
    private(set) var history: [ScanResult] = []
    /// Storico in caricamento (lettura della chiave dal Portachiavi).
    private(set) var historyLoading = false
    /// Avviso sullo storico (es. scansioni cifrate non decifrabili).
    private(set) var historyWarning: String?
    var selectedHostID: Host.ID?
    /// Mostra la configurazione guidata (menu Aiuto).
    var showOnboarding = false
    /// Scheda dei risultati (Dispositivi / Problemi / Rete).
    var resultsMode: ResultsView.Mode = .devices
    var selectedHistoryID: ScanResult.ID?

    /// Dispositivi che l'utente ha segnato come noti (chiave = MAC o IP).
    private(set) var trusted: Set<String>

    /// Stato del privileged helper.
    private(set) var helperState: HelperState = .checking
    private(set) var helperBusy = false

    private let store = ScanHistoryStore()
    private var scanTask: Task<Void, Never>?
    @ObservationIgnored private var activationObserver: NSObjectProtocol?
    @ObservationIgnored private var openScanObserver: NSObjectProtocol?
    /// Scansioni programmate.
    private(set) var scheduler: ScanScheduler!

    /// Notifica interna per aprire una scansione (es. clic su una notifica).
    static let openScanNotification = Notification.Name("SubnetScout.openScan")

    init() {
        trusted = Set(UserDefaults.standard.stringArray(forKey: "trustedDevices") ?? [])
        refreshEnvironment()
        // Lo storico è cifrato con una chiave nel Portachiavi: leggerla può far comparire
        // una richiesta di macOS (dopo ogni aggiornamento, senza Developer ID). Lo si
        // carica in background per non bloccare l'interfaccia nel frattempo.
        historyLoading = true
        let store = self.store
        Task.detached(priority: .userInitiated) {
            let (all, unreadable) = store.loadAllReportingUnreadable()
            await MainActor.run {
                self.history = all + self.history.filter { s in !all.contains { $0.id == s.id } }
                self.historyLoading = false
                if unreadable > 0 {
                    self.historyWarning = "\(unreadable) scansioni salvate non sono leggibili: la chiave di cifratura nel Portachiavi manca, è cambiata o l'accesso è stato negato."
                }
                if self.current == nil, let last = self.history.first { self.show(last) }
            }
        }
        Task { await refreshHelper() }
        // Dopo l'approvazione in Impostazioni di Sistema l'utente torna all'app: ricontrolla.
        activationObserver = NotificationCenter.default.addObserver(
            forName: NSApplication.didBecomeActiveNotification, object: nil, queue: .main
        ) { [weak self] _ in
            Task { @MainActor in
                self?.refreshEnvironment()   // la rete può essere cambiata (Wi-Fi diverso)
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

    /// Il helper è registrato e risponde (anche se nmap non è utilizzabile come root).
    var helperIsReachable: Bool { if case .ready = helperState { true } else { false } }

    /// Come verrà eseguita la scansione con «Come amministratore» attivo.
    /// Con il helper pronto tutte le scansioni passano da lui: niente password e
    /// niente limiti del permesso «Rete locale». «Come amministratore» decide solo
    /// gli argomenti (OS detection, UDP, sonda DHCP).
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
                helperState = .error("Installazione non riuscita: \(error.localizedDescription)")
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
                // l'utente ha annullato la richiesta password
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
                phase = .failed("Disinstallazione non riuscita: \(error.localizedDescription)")
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

    // MARK: Scansione

    enum ScanOrigin { case manual, scheduled }

    func startScan() {
        guard !isScanning else { return }
        do {
            launch(targets: try TargetParser.parse(target), profile: profile, privileged: privileged, origin: .manual)
        } catch {
            phase = .failed(error.localizedDescription)
        }
    }

    /// Avvia una scansione. Usata dal pulsante e dalla pianificazione.
    /// - Returns: false se non è partita (scansione già in corso, nmap assente).
    @discardableResult
    func launch(targets: [String], profile: ScanProfile, privileged: Bool, origin: ScanOrigin) -> Bool {
        guard !isScanning, let nmapPath else { return false }
        // Senza rotta predefinita il Mac non è in rete: una scansione della LAN darebbe 0 dispositivi.
        if origin == .manual, PrivateTargets.allPrivate(targets), NetworkInfo.defaultRoute().gateway == nil {
            phase = .failed("Il Mac non risulta collegato a nessuna rete. Collegati al Wi-Fi o via cavo e riprova.")
            return false
        }
        let engine = ScanEngine(nmapPath: nmapPath)
        // Il helper scansiona solo reti private: i target pubblici vanno con nmap locale.
        let helperForThis = usesHelper && PrivateTargets.allPrivate(targets)
        // Le scansioni programmate non chiedono mai la password.
        let askPassword = privileged && !helperForThis && origin == .manual
        let executor: any NmapExecutor = helperForThis
            ? HelperNmapExecutor(fullPrivileges: privileged)
            : LocalNmapExecutor(nmapPath: nmapPath, askPassword: askPassword)
        phase = .scanning(progress: 0)
        scanStartedAt = Date()
        scanSummary = profile.name + (helperForThis ? " · helper" : askPassword ? " · password" : " · utente")
            + (origin == .scheduled ? " · programmata" : "")

        // ARP e UPnP: con il helper attivo li legge lui (non è soggetto al permesso
        // «Rete locale», che macOS può negare all'app); se fallisce, li legge l'app.
        let probe: ScanEngine.ProbeProvider? = helperIsReachable ? { @Sendable in
            if let p = try? await HelperClient.networkProbe() { return p }
            return await NetworkProbe.run(source: "app")
        } : nil

        // CVE da NVD: solo se attivata nelle impostazioni (invia prodotto e versione).
        let cveLookup: NVDClient? = CVESettings.enabled
            ? NVDClient(options: .init(apiKey: CVESettings.apiKey())) : nil
        scanStage = ""

        // Scansione precedente dello stesso target: serve per le regole che confrontano la rete.
        let previous = history.filter { $0.target == targets.joined(separator: " ") }.max { $0.finishedAt < $1.finishedAt }
        let trustedNow = trusted
        // Evita che App Nap rallenti una scansione con la finestra nascosta.
        let activity = ProcessInfo.processInfo.beginActivity(options: [.userInitiated, .idleSystemSleepDisabled],
                                                             reason: "Scansione di rete")

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
                // Fuori dal thread principale: la chiave del Portachiavi può richiedere conferma.
                let store = self.store
                if case .failure(let error) = await Task.detached(operation: { try store.save(result) }).result {
                    historyWarning = "Scansione non salvata nello storico: \(error.localizedDescription)"
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
                // Le scansioni programmate falliscono in silenzio (ritentano al prossimo turno).
                phase = origin == .manual ? .failed(error.localizedDescription) : .idle
            }
        }
        return true
    }

    /// Apre la scansione indicata (es. dal clic su una notifica).
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

    // MARK: Dispositivi fidati

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
            phase = .failed("Esportazione non riuscita: \(error.localizedDescription)")
        }
    }

    /// Apre il report nel browser senza chiedere dove salvarlo.
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
