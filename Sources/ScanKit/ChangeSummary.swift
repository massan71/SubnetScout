import Foundation

/// What changed between two scans of the same target, reduced to what deserves
/// a notification. It holds only counts: the notification may appear on the lock
/// screen, so no IPs, names or MACs.
public struct ChangeSummary: Equatable, Sendable {
    public var target: String
    /// New devices not marked as known.
    public var newDevices: Int
    public var openedPorts: Int
    /// New findings (CVEs excluded) with severity at least `minimumSeverity`.
    public var newIssues: Int
    /// Services with known vulnerabilities that appeared in this scan.
    public var newCVEServices: Int
    public var worst: Severity?

    /// - Parameter previous: nil on the first scan of the target: it is the baseline,
    ///   so it triggers no notifications.
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
        if let worst, worst >= .high { return "SubnetScout: security issues on \(target)" }
        return "SubnetScout: changes on \(target)"
    }

    public var body: String {
        var parts: [String] = []
        func plural(_ n: Int, _ one: String, _ many: String) -> String { "\(n) \(n == 1 ? one : many)" }
        if newDevices > 0 { parts.append(plural(newDevices, "new device", "new devices")) }
        if openedPorts > 0 { parts.append(plural(openedPorts, "opened port", "opened ports")) }
        if newIssues > 0 { parts.append(plural(newIssues, "new issue", "new issues")) }
        if newCVEServices > 0 { parts.append(plural(newCVEServices, "service with new CVEs", "services with new CVEs")) }
        var text = parts.joined(separator: " · ")
        if let worst { text += " (highest severity: \(worst.label.lowercased()))" }
        return text
    }
}
