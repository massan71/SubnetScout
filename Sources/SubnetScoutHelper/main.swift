// SubnetScoutHelper — daemon root registrato con SMAppService.
//
// Espone via XPC (servizio Mach "net.sangalli.SubnetScout.helper") solo
// l'esecuzione di nmap con i profili predefiniti di ScanKit. Sicurezza:
//  • accetta connessioni solo dall'app SubnetScout (requisito di firma);
//  • rivalida profilo e target; gli argomenti di nmap li costruisce lui;
//  • esegue solo un nmap interamente di proprietà di root (vedi TrustedNmap);
//  • ambiente azzerato, cwd "/", si chiude da solo quando è inattivo.

import Foundation
import Security
import os
import ScanKit

let log = Logger(subsystem: HelperConstants.helperIdentifier, category: "helper")

// MARK: - Requisito di firma del client

/// Il client deve essere firmato come il helper: stesso Team ID (Developer ID),
/// stesso certificato radice (certificato proprio) oppure, con firma ad-hoc in
/// sviluppo, almeno lo stesso identificatore.
func clientRequirement() -> String {
    let kind = CodeSigning.current()
    if kind == .adHoc {
        log.warning("Helper con firma ad-hoc: il client viene verificato solo per identificatore")
    }
    return CodeSigning.requirement(forPeer: HelperConstants.appIdentifier, signedLike: kind)
}

// MARK: - Spegnimento quando inattivo

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
                log.info("Inattivo, uscita")
                exit(0)
            }
        }
    }
}

// MARK: - Servizio

final class HelperService: NSObject, ScanHelperProtocol, @unchecked Sendable {
    private static let maxConcurrentScans = 2
    private static let lock = NSLock()
    nonisolated(unsafe) private static var running = 0 // protetto da `lock`

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
            log.error("adoptNmap rifiutato: autorizzazione non valida")
            return reply(nil, NmapAdopter.AdoptError.unauthorized.localizedDescription)
        }
        do {
            let resolved = try NmapAdopter.adopt()
            log.info("nmap adottato in \(resolved.binary, privacy: .public)")
            reply(resolved.binary, nil)
        } catch {
            log.error("adoptNmap fallito: \(error.localizedDescription, privacy: .public)")
            reply(nil, error.localizedDescription)
        }
    }

    func runScan(id: String, profile: String, targets: [String],
                 reply: @escaping @Sendable (Data?, String?) -> Void) {
        guard UUID(uuidString: id) != nil else { return reply(nil, "ID di scansione non valido.") }
        guard let profile = ScanProfile(rawValue: profile) else { return reply(nil, "Profilo non valido.") }
        let validated: [String]
        do {
            validated = try TargetParser.parse(targets.joined(separator: " "))
        } catch {
            return reply(nil, error.localizedDescription)
        }
        let nmap: TrustedNmap.Resolved
        switch TrustedNmap.resolve() {
        case .success(let n): nmap = n
        case .failure(let p): return reply(nil, p.localizedDescription)
        }
        guard Self.acquireSlot() else { return reply(nil, "Troppe scansioni in corso.") }

        let client = ClientProxy(connection?.remoteObjectProxy as? ScanHelperClientProtocol)
        let args = profile.arguments(privileged: true) + ["--datadir", nmap.dataDir]
        log.info("Scansione \(id, privacy: .public): profilo \(profile.rawValue, privacy: .public), \(validated.count) target")

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
                reply(nil, "Scansione annullata.")
            } catch {
                reply(nil, error.localizedDescription)
            }
        }
        lock.lock(); tasks[id] = task; lock.unlock()
    }

    func networkProbe(reply: @escaping @Sendable (Data?, String?) -> Void) {
        guard Self.acquireSlot() else { return reply(nil, "Troppe operazioni in corso.") }
        Task {
            defer { Self.releaseSlot() }
            let probe = await NetworkProbe.run(source: "helper")
            log.info("Sonda di rete: \(probe.arp.count) voci ARP, \(probe.upnpGateways.count) router UPnP")
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

/// I proxy XPC sono thread-safe: il box serve solo a dirlo al compilatore.
struct ClientProxy: @unchecked Sendable {
    let proxy: ScanHelperClientProtocol?
    init(_ proxy: ScanHelperClientProtocol?) { self.proxy = proxy }
}

// MARK: - Listener

final class ListenerDelegate: NSObject, NSXPCListenerDelegate {
    let requirement = clientRequirement()
    let idle = IdleTracker(timeout: 30)

    func listener(_ listener: NSXPCListener, shouldAcceptNewConnection c: NSXPCConnection) -> Bool {
        // I messaggi di un client che non soddisfa il requisito vengono rifiutati
        // e la connessione invalidata.
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
log.info("SubnetScoutHelper avviato (pid \(getpid()), requisito client: \(delegate.requirement, privacy: .public))")
dispatchMain()
