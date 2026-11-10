import Foundation

/// Cosa è cambiato tra due scansioni dello stesso target, ridotto a ciò che merita
/// una notifica. Contiene solo conteggi: la notifica può comparire sullo schermo
/// bloccato, quindi niente IP, nomi o MAC.
public struct ChangeSummary: Equatable, Sendable {
    public var target: String
    /// Dispositivi nuovi e non segnati come noti.
    public var newDevices: Int
    public var openedPorts: Int
    /// Nuovi problemi (esclusi CVE) con gravità almeno `minimumSeverity`.
    public var newIssues: Int
    /// Servizi con vulnerabilità note comparse in questa scansione.
    public var newCVEServices: Int
    public var worst: Severity?

    /// - Parameter previous: nil alla prima scansione del target: fa da riferimento,
    ///   quindi non genera notifiche.
    public init(previous: ScanResult?, current: ScanResult, trusted: Set<String>,
                minimumSeverity: Severity = .medium) {
        target = current.target
        guard let previous else {
            newDevices = 0; openedPorts = 0; newIssues = 0; newCVEServices = 0; worst = nil
            return
        }
        let diff = ScanDiff(previous: previous, current: current)
        newDevices = diff.newHosts.filter { !trusted.contains($0.deviceKey) }.count
        openedPorts = diff.openedPorts.count
        let relevant = diff.newFindings.filter { $0.severity >= minimumSeverity }
        newIssues = relevant.filter { $0.ruleID != "known-cve" }.count
        newCVEServices = relevant.filter { $0.ruleID == "known-cve" }.count
        worst = relevant.map(\.severity).max()
    }

    public var isEmpty: Bool { newDevices == 0 && openedPorts == 0 && newIssues == 0 && newCVEServices == 0 }

    public var title: String {
        if let worst, worst >= .high { return "SubnetScout: problemi di sicurezza su \(target)" }
        return "SubnetScout: cambiamenti su \(target)"
    }

    public var body: String {
        var parts: [String] = []
        func plural(_ n: Int, _ one: String, _ many: String) -> String { "\(n) \(n == 1 ? one : many)" }
        if newDevices > 0 { parts.append(plural(newDevices, "nuovo dispositivo", "nuovi dispositivi")) }
        if openedPorts > 0 { parts.append(plural(openedPorts, "porta aperta", "porte aperte")) }
        if newIssues > 0 { parts.append(plural(newIssues, "nuovo problema", "nuovi problemi")) }
        if newCVEServices > 0 { parts.append(plural(newCVEServices, "servizio con nuove CVE", "servizi con nuove CVE")) }
        var text = parts.joined(separator: " · ")
        if let worst { text += " (gravità massima: \(worst.label.lowercased()))" }
        return text
    }
}
