import SwiftUI
import AppKit
import ServiceManagement
import UserNotifications
import ScanKit

// MARK: - Impostazioni

/// Impostazioni della scansione programmata (UserDefaults).
enum ScheduleSettings {
    static let enabledKey = "scheduleEnabled"
    static let intervalKey = "scheduleInterval"
    static let profileKey = "scheduleProfile"
    static let targetKey = "scheduleTarget"
    static let fullPrivilegesKey = "scheduleFullPrivileges"
    static let notifyKey = "scheduleNotify"
    static let lastRunKey = "scheduleLastRun"
    static let menuBarKey = "showMenuBar"

    enum Interval: Double, CaseIterable, Identifiable {
        case hourly = 3600, every6h = 21_600, daily = 86_400, weekly = 604_800
        var id: Double { rawValue }
        var label: String {
            switch self {
            case .hourly: "Ogni ora"
            case .every6h: "Ogni 6 ore"
            case .daily: "Ogni giorno"
            case .weekly: "Ogni settimana"
            }
        }
    }

    static var defaults: UserDefaults { .standard }
    static var enabled: Bool { defaults.bool(forKey: enabledKey) }
    static var interval: TimeInterval {
        let v = defaults.double(forKey: intervalKey)
        return v > 0 ? v : Interval.daily.rawValue
    }
    static var profile: ScanProfile { ScanProfile(rawValue: defaults.string(forKey: profileKey) ?? "") ?? .quick }
    /// Vuoto = rete dell'interfaccia attiva al momento della scansione.
    static var target: String { defaults.string(forKey: targetKey) ?? "" }
    static var fullPrivileges: Bool { defaults.bool(forKey: fullPrivilegesKey) }
    static var notify: Bool { defaults.object(forKey: notifyKey) as? Bool ?? true }
    static var showMenuBar: Bool { defaults.object(forKey: menuBarKey) as? Bool ?? true }
    static var lastRun: Date? {
        get { defaults.object(forKey: lastRunKey) as? Date }
        set { defaults.set(newValue, forKey: lastRunKey) }
    }
}

// MARK: - Pianificatore

/// Controlla ogni minuto (e al risveglio del Mac) se è ora della scansione
/// programmata. Lo stato sta in UserDefaults, quindi una scansione persa mentre
/// il Mac era spento o l'app chiusa parte appena possibile.
@MainActor
@Observable
final class ScanScheduler {
    private weak var model: AppModel?
    @ObservationIgnored private var timer: Timer?
    @ObservationIgnored private var wakeObserver: NSObjectProtocol?
    /// Ultimo motivo per cui una scansione programmata non è partita.
    private(set) var lastSkipReason: String?
    /// Aggiornato a ogni controllo, per l'interfaccia.
    private(set) var nextRun: Date?

    init(model: AppModel) {
        self.model = model
        timer = Timer.scheduledTimer(withTimeInterval: 60, repeats: true) { [weak self] _ in
            Task { @MainActor in self?.tick() }
        }
        timer?.tolerance = 15
        wakeObserver = NSWorkspace.shared.notificationCenter.addObserver(
            forName: NSWorkspace.didWakeNotification, object: nil, queue: .main
        ) { [weak self] _ in
            // Lascia il tempo alla rete di tornare su.
            Task { @MainActor in
                try? await Task.sleep(for: .seconds(60))
                self?.tick()
            }
        }
        refresh()
    }

    /// Da chiamare quando cambiano le impostazioni.
    func settingsChanged() {
        if ScheduleSettings.enabled, ScheduleSettings.lastRun == nil {
            // Prima attivazione: una scansione di riferimento tra un minuto.
            ScheduleSettings.lastRun = Date().addingTimeInterval(-ScheduleSettings.interval + 60)
            Notifier.requestAuthorization()
        }
        refresh()
    }

    private func refresh() {
        guard ScheduleSettings.enabled else { nextRun = nil; return }
        nextRun = (ScheduleSettings.lastRun ?? Date()).addingTimeInterval(ScheduleSettings.interval)
    }

    func tick() {
        refresh()
        guard ScheduleSettings.enabled, let nextRun, Date() >= nextRun, let model else { return }
        guard !model.isScanning else { lastSkipReason = "Un'altra scansione era in corso."; return }
        guard let targets = Self.resolveTargets() else {
            lastSkipReason = "Nessuna rete locale adatta (offline, oppure la rete è più grande di /22)."
            return
        }
        if model.launch(targets: targets, profile: ScheduleSettings.profile,
                        privileged: ScheduleSettings.fullPrivileges, origin: .scheduled) {
            ScheduleSettings.lastRun = Date()
            lastSkipReason = nil
            refresh()
        }
    }

    /// Target salvato oppure la rete dell'interfaccia della rotta predefinita
    /// (solo se non più grande di /22, per non far partire scansioni enormi da sole).
    static func resolveTargets() -> [String]? {
        let saved = ScheduleSettings.target.trimmingCharacters(in: .whitespaces)
        if !saved.isEmpty { return try? TargetParser.parse(saved) }
        let route = NetworkInfo.defaultRoute()
        guard let name = route.interface,
              let iface = NetworkInfo.interfaces().first(where: { $0.name == name }),
              iface.prefixLength >= 22 else { return nil }
        return [iface.cidr]
    }
}

// MARK: - Notifiche

enum Notifier {
    static let scanIDKey = "scanID"

    static func requestAuthorization() {
        UNUserNotificationCenter.current().requestAuthorization(options: [.alert, .sound]) { _, _ in }
    }

    static func postTest() {
        UNUserNotificationCenter.current().requestAuthorization(options: [.alert, .sound]) { granted, _ in
            guard granted else {
                DispatchQueue.main.async {
                    NSWorkspace.shared.open(URL(string: "x-apple.systempreferences:com.apple.Notifications-Settings.extension")!)
                }
                return
            }
            let content = UNMutableNotificationContent()
            content.title = "SubnetScout"
            content.body = "Le notifiche funzionano: riceverai un avviso quando una scansione programmata trova cambiamenti."
            UNUserNotificationCenter.current().add(UNNotificationRequest(identifier: "test", content: content, trigger: nil))
        }
    }

    static func post(_ summary: ChangeSummary, scanID: UUID) {
        let content = UNMutableNotificationContent()
        content.title = summary.title
        content.body = summary.body
        content.sound = (summary.worst ?? .info) >= .high ? .default : nil
        content.userInfo = [scanIDKey: scanID.uuidString]
        content.threadIdentifier = "scheduled-scans"
        let request = UNNotificationRequest(identifier: scanID.uuidString, content: content, trigger: nil)
        UNUserNotificationCenter.current().add(request)
    }
}

// MARK: - Avvio all'accesso

enum LoginItem {
    static var isEnabled: Bool { SMAppService.mainApp.status == .enabled }

    static func set(_ on: Bool) throws {
        if on { try SMAppService.mainApp.register() } else { try SMAppService.mainApp.unregister() }
    }
}
