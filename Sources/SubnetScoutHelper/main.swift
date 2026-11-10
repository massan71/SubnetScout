// SubnetScoutHelper — root daemon registered with SMAppService.
//
// Exposes over XPC (Mach service "net.sangalli.SubnetScout.helper") only
// running nmap with ScanKit's predefined profiles. Security:
//  • accepts connections only from the SubnetScout app (signing requirement);
//  • re-validates profile and targets; it builds the nmap arguments itself;
//  • runs only an nmap entirely owned by root (see TrustedNmap);
//  • cleared environment, cwd "/", exits by itself when idle.

import Foundation
import Security
import os
import ScanKit

let log = Logger(subsystem: HelperConstants.helperIdentifier, category: "helper")

// MARK: - Client signing requirement

/// The client must be signed like the helper: same Team ID (Developer ID),
/// same root certificate (own certificate) or, with ad-hoc signing in
/// development, at least the same identifier.
func clientRequirement() -> String {
    let kind = CodeSigning.current()
    if kind == .adHoc {
        log.warning("Ad-hoc signed helper: the client is verified by identifier only")
    }
    return CodeSigning.requirement(forPeer: HelperConstants.appIdentifier, signedLike: kind)
}

// MARK: - Shutdown when idle

final class IdleTracker: @unchecked Sendable {
    private let lock = NSLock()
    private var active = 0
    private var generation = 0
    private let timeout: TimeInterval

    init(timeout: TimeInterval) {
        self.timeout = timeout
        scheduleExit()
    }

    func opened() {
        lock.lock(); active += 1; generation += 1; lock.unlock()
    }

    func closed() {
        lock.lock(); active -= 1; lock.unlock()
        scheduleExit()
    }

    private func scheduleExit() {
        lock.lock(); generation += 1; let gen = generation; lock.unlock()
        DispatchQueue.main.asyncAfter(deadline: .now() + timeout) { [self] in
            lock.lock(); let idle = active == 0 && gen == generation; lock.unlock()
            if idle {
                log.info("Idle, exiting")
                exit(0)
            }
        }
    }
}

// MARK: - Service

final class HelperService: NSObject, ScanHelperProtocol, @unchecked Sendable {
    private static let maxConcurrentScans = 2
    private static let lock = NSLock()
    nonisolated(unsafe) private static var running = 0 // protected by `lock`

    private weak var connection: NSXPCConnection?
    private let lock = NSLock()
    private var tasks: [String: Task<Void, Never>] = [:]

    init(connection: NSXPCConnection) {
        self.connection = connection
    }

    func info(reply: @escaping @Sendable (String, String?, String?, Bool) -> Void) {
        let canAdopt = TrustedNmap.canAdopt
        switch TrustedNmap.resolve() {
        case .success(let n): reply(HelperConstants.protocolVersion, n.binary, nil, canAdopt)
        case .failure(let p): reply(HelperConstants.protocolVersion, nil, p.localizedDescription, canAdopt)
        }
    }

    func adoptNmap(authorization: Data, reply: @escaping @Sendable (String?, String?) -> Void) {
        guard NmapAdopter.verifyAdmin(authorization) else {
            log.error("adoptNmap refused: invalid authorization")
            return reply(nil, NmapAdopter.AdoptError.unauthorized.localizedDescription)
        }
        do {
            let resolved = try NmapAdopter.adopt()
            log.info("nmap adopted at \(resolved.binary, privacy: .public)")
            reply(resolved.binary, nil)
        } catch {
            log.error("adoptNmap failed: \(error.localizedDescription, privacy: .public)")
            reply(nil, error.localizedDescription)
        }
    }

    func runScan(id: String, profile: String, targets: [String], fullPrivileges: Bool,
                 reply: @escaping @Sendable (Data?, String?) -> Void) {
        guard UUID(uuidString: id) != nil else { return reply(nil, "Invalid scan ID.") }
        guard let profile = ScanProfile(rawValue: profile) else { return reply(nil, "Invalid profile.") }
        let validated: [String]
        do {
            // Syntax + private networks only (hostnames become already-verified IPs).
            validated = try PrivateTargets.validate(TargetParser.parse(targets.joined(separator: " ")))
        } catch {
            return reply(nil, error.localizedDescription)
        }
        let nmap: TrustedNmap.Resolved
        switch TrustedNmap.resolve() {
        case .success(let n): nmap = n
        case .failure(let p): return reply(nil, p.localizedDescription)
        }
        guard Self.acquireSlot() else { return reply(nil, "Too many scans in progress.") }

        let client = ClientProxy(connection?.remoteObjectProxy as? ScanHelperClientProtocol)
        let args = profile.arguments(privileged: fullPrivileges) + ["--datadir", nmap.dataDir]
        log.info("Scan \(id, privacy: .public): profile \(profile.rawValue, privacy: .public), \(validated.count) target")

        let task = Task { [weak self] in
            defer {
                Self.releaseSlot()
                self?.removeTask(id)
            }
            do {
                let data = try await NmapRunner(nmapPath: nmap.binary).runDirect(
                    arguments: args,
                    targets: validated,
                    environment: ["PATH": "/usr/bin:/bin:/usr/sbin:/sbin", "HOME": "/var/root", "LANG": "C"],
                    workingDirectory: URL(fileURLWithPath: "/"),
                    onProgress: { client.proxy?.scanProgress(id: id, value: $0) })
                reply(data, nil)
            } catch is CancellationError {
                reply(nil, "Scan cancelled.")
            } catch {
                reply(nil, error.localizedDescription)
            }
        }
        lock.lock(); tasks[id] = task; lock.unlock()
    }

    func networkProbe(reply: @escaping @Sendable (Data?, String?) -> Void) {
        guard Self.acquireSlot() else { return reply(nil, "Too many operations in progress.") }
        Task {
            defer { Self.releaseSlot() }
            let probe = await NetworkProbe.run(source: "helper")
            log.info("Network probe: \(probe.arp.count) ARP entries, \(probe.upnpGateways.count) UPnP routers")
            do {
                reply(try JSONEncoder().encode(probe), nil)
            } catch {
                reply(nil, error.localizedDescription)
            }
        }
    }

    func cancelScan(id: String) {
        lock.lock(); let t = tasks[id]; lock.unlock()
        t?.cancel()
    }

    func cancelAll() {
        lock.lock(); let all = Array(tasks.values); lock.unlock()
        all.forEach { $0.cancel() }
    }

    private func removeTask(_ id: String) {
        lock.lock(); tasks[id] = nil; lock.unlock()
    }

    private static func acquireSlot() -> Bool {
        lock.lock(); defer { lock.unlock() }
        guard running < maxConcurrentScans else { return false }
        running += 1
        return true
    }

    private static func releaseSlot() {
        lock.lock(); running -= 1; lock.unlock()
    }
}

/// XPC proxies are thread-safe: the box only tells the compiler so.
struct ClientProxy: @unchecked Sendable {
    let proxy: ScanHelperClientProtocol?
    init(_ proxy: ScanHelperClientProtocol?) { self.proxy = proxy }
}

// MARK: - Listener

final class ListenerDelegate: NSObject, NSXPCListenerDelegate {
    let requirement = clientRequirement()
    let idle = IdleTracker(timeout: 30)

    func listener(_ listener: NSXPCListener, shouldAcceptNewConnection c: NSXPCConnection) -> Bool {
        // Messages from a client that does not meet the requirement are rejected
        // and the connection invalidated.
        c.setCodeSigningRequirement(requirement)
        c.exportedInterface = HelperInterfaces.service()
        c.remoteObjectInterface = HelperInterfaces.client()
        let service = HelperService(connection: c)
        c.exportedObject = service
        let idle = self.idle
        c.invalidationHandler = {
            service.cancelAll()
            idle.closed()
        }
        idle.opened()
        c.resume()
        return true
    }
}

let delegate = ListenerDelegate()
let listener = NSXPCListener(machServiceName: HelperConstants.machServiceName)
listener.delegate = delegate
listener.resume()
log.info("SubnetScoutHelper started (pid \(getpid()), client requirement: \(delegate.requirement, privacy: .public))")
dispatchMain()
