import Foundation
import ServiceManagement
import ScanKit

/// Stato del privileged helper come lo vede l'app.
enum HelperState: Equatable {
    /// L'app non gira dal bundle (es. `swift run`): helper non disponibile.
    case unavailable
    case notInstalled
    case needsApproval
    /// Registrato e raggiungibile. `problem` è valorizzato se nmap non è eseguibile come root in sicurezza;
    /// `canAdopt` se /Applications/nmap.app può essere copiato in una posizione protetta.
    case ready(nmapPath: String?, problem: String?, canAdopt: Bool)
    case error(String)

    var canScan: Bool {
        if case .ready(_, nil, _) = self { true } else { false }
    }
}

enum HelperError: LocalizedError {
    case connection(String)
    case remote(String)
    case versionMismatch(String)

    var errorDescription: String? {
        switch self {
        case .connection(let m): "Impossibile contattare il helper: \(m)"
        case .remote(let m): m
        case .versionMismatch(let v): "Versione del helper non compatibile (\(v)). Reinstalla il helper."
        }
    }
}

enum HelperClient {
    static var service: SMAppService { .daemon(plistName: HelperConstants.plistName) }

    static var isBundled: Bool {
        let plist = Bundle.main.bundleURL
            .appending(path: "Contents/Library/LaunchDaemons/\(HelperConstants.plistName)")
        return Bundle.main.bundleURL.pathExtension == "app" && FileManager.default.fileExists(atPath: plist.path)
    }

    static func currentState() async -> HelperState {
        guard isBundled else { return .unavailable }
        switch service.status {
        case .notRegistered, .notFound: return .notInstalled
        case .requiresApproval: return .needsApproval
        case .enabled:
            do {
                let info = try await info()
                guard info.version == HelperConstants.protocolVersion else {
                    return .error(HelperError.versionMismatch(info.version).localizedDescription)
                }
                return .ready(nmapPath: info.nmapPath, problem: info.problem, canAdopt: info.canAdopt)
            } catch {
                return .error(error.localizedDescription)
            }
        @unknown default:
            return .error("Stato del helper sconosciuto.")
        }
    }

    /// Registra il daemon. Al primo giro macOS chiede l'approvazione in
    /// Impostazioni di Sistema › Generali › Elementi login ed estensioni.
    ///
    /// Se è già registrato (es. dopo una nuova build con firma diversa, che launchd
    /// rifiuta con OS_REASON_CODESIGNING) prima annulla la registrazione.
    static func install() async throws {
        if service.status == .enabled || service.status == .requiresApproval {
            try? await service.unregister()
        }
        do {
            try service.register()
        } catch {
            // "Operation not permitted" = registrato ma in attesa di approvazione.
            if service.status == .requiresApproval { return }
            throw error
        }
    }

    static func uninstall() async throws {
        try await service.unregister()
    }

    static func openApprovalSettings() {
        SMAppService.openSystemSettingsLoginItems()
    }

    // MARK: XPC

    static func makeConnection(exporting receiver: ScanHelperClientProtocol? = nil) -> NSXPCConnection {
        let c = NSXPCConnection(machServiceName: HelperConstants.machServiceName, options: .privileged)
        c.remoteObjectInterface = HelperInterfaces.service()
        if let receiver {
            c.exportedInterface = HelperInterfaces.client()
            c.exportedObject = receiver
        }
        // Verifichiamo anche noi chi risponde sul servizio Mach.
        c.setCodeSigningRequirement(CodeSigning.requirement(forPeer: HelperConstants.helperIdentifier))
        c.resume()
        return c
    }

    struct Info: Sendable { var version: String; var nmapPath: String?; var problem: String?; var canAdopt: Bool }

    static func info() async throws -> Info {
        let c = makeConnection()
        defer { c.invalidate() }
        return try await withCheckedThrowingContinuation { (cont: CheckedContinuation<Info, Error>) in
            let once = ResumeOnce(cont)
            let proxy = c.remoteObjectProxyWithErrorHandler { once.resume(throwing: HelperError.connection($0.localizedDescription)) }
            guard let helper = proxy as? ScanHelperProtocol else {
                return once.resume(throwing: HelperError.connection("proxy non valido"))
            }
            helper.info { version, path, problem, canAdopt in
                once.resume(returning: Info(version: version, nmapPath: path, problem: problem, canAdopt: canAdopt))
            }
        }
    }
}

// MARK: - Adozione di nmap.app

extension HelperClient {
    /// Chiede la password amministratore (finestra di sistema) e fa copiare al helper
    /// /Applications/nmap.app in una cartella di proprietà di root.
    static func adoptNmap() async throws -> String {
        let auth = try await Task.detached(priority: .userInitiated) {
            try AdminAuthorization(prompt: "SubnetScout vuole copiare nmap in una cartella protetta per eseguire le scansioni come amministratore senza chiedere la password.")
        }.value
        defer { auth.release() }

        let c = makeConnection()
        defer { c.invalidate() }
        return try await withCheckedThrowingContinuation { (cont: CheckedContinuation<String, Error>) in
            let once = ResumeOnce(cont)
            let proxy = c.remoteObjectProxyWithErrorHandler { once.resume(throwing: HelperError.connection($0.localizedDescription)) }
            guard let helper = proxy as? ScanHelperProtocol else {
                return once.resume(throwing: HelperError.connection("proxy non valido"))
            }
            helper.adoptNmap(authorization: auth.externalForm) { path, error in
                if let path { once.resume(returning: path) } else {
                    once.resume(throwing: HelperError.remote(error ?? "Copia di nmap non riuscita."))
                }
            }
        }
    }
}

/// AuthorizationRef con il diritto admin già ottenuto (password inserita dall'utente).
final class AdminAuthorization: @unchecked Sendable {
    struct Cancelled: LocalizedError {
        var errorDescription: String? { "Autorizzazione annullata." }
    }

    private let ref: AuthorizationRef
    let externalForm: Data

    init(prompt: String) throws {
        var ref: AuthorizationRef?
        guard AuthorizationCreate(nil, nil, [], &ref) == errAuthorizationSuccess, let ref else {
            throw HelperError.connection("AuthorizationCreate non riuscito")
        }
        var status = errAuthorizationDenied
        let promptC = strdup(prompt)!
        defer { Darwin.free(promptC) }
        HelperConstants.adminRight.withCString { name in
            kAuthorizationEnvironmentPrompt.withCString { promptKey in
                var right = AuthorizationItem(name: name, valueLength: 0, value: nil, flags: 0)
                var envItem = AuthorizationItem(name: promptKey, valueLength: strlen(promptC), value: promptC, flags: 0)
                withUnsafeMutablePointer(to: &right) { rp in
                    withUnsafeMutablePointer(to: &envItem) { ep in
                        var rights = AuthorizationRights(count: 1, items: rp)
                        var env = AuthorizationEnvironment(count: 1, items: ep)
                        status = AuthorizationCopyRights(ref, &rights, &env,
                                                         [.interactionAllowed, .extendRights, .preAuthorize], nil)
                    }
                }
            }
        }
        guard status == errAuthorizationSuccess else {
            AuthorizationFree(ref, [.destroyRights])
            if status == errAuthorizationCanceled { throw Cancelled() }
            throw HelperError.remote("Autorizzazione negata (\(status)).")
        }
        var ext = AuthorizationExternalForm()
        guard AuthorizationMakeExternalForm(ref, &ext) == errAuthorizationSuccess else {
            AuthorizationFree(ref, [.destroyRights])
            throw HelperError.connection("AuthorizationMakeExternalForm non riuscito")
        }
        self.ref = ref
        self.externalForm = withUnsafeBytes(of: &ext) { Data($0) }
    }

    /// Distrugge i diritti: la stessa autorizzazione non è riutilizzabile.
    func release() { AuthorizationFree(ref, [.destroyRights]) }
}

/// Esegue le scansioni tramite il helper root: niente password, con avanzamento.
struct HelperNmapExecutor: NmapExecutor {
    var isPrivileged: Bool { true }

    func execute(profile: ScanProfile, targets: [String],
                 onProgress: @escaping @Sendable (Double) -> Void) async throws -> Data {
        let id = UUID().uuidString
        let receiver = ProgressReceiver(id: id, onProgress: onProgress)
        let connection = ConnectionBox(HelperClient.makeConnection(exporting: receiver))
        defer { connection.value.invalidate() }

        do {
            return try await withTaskCancellationHandler {
                try await withCheckedThrowingContinuation { (cont: CheckedContinuation<Data, Error>) in
                    let once = ResumeOnce(cont)
                    let proxy = connection.value.remoteObjectProxyWithErrorHandler {
                        once.resume(throwing: HelperError.connection($0.localizedDescription))
                    }
                    guard let helper = proxy as? ScanHelperProtocol else {
                        return once.resume(throwing: HelperError.connection("proxy non valido"))
                    }
                    helper.runScan(id: id, profile: profile.rawValue, targets: targets) { data, error in
                        if let data {
                            once.resume(returning: data)
                        } else {
                            once.resume(throwing: HelperError.remote(error ?? "Errore sconosciuto del helper."))
                        }
                    }
                }
            } onCancel: {
                (connection.value.remoteObjectProxy as? ScanHelperProtocol)?.cancelScan(id: id)
            }
        } catch {
            if Task.isCancelled { throw CancellationError() }
            throw error
        }
    }
}

// MARK: - Helper per la concorrenza

/// Riceve l'avanzamento dal helper (chiamato su una coda XPC).
final class ProgressReceiver: NSObject, ScanHelperClientProtocol, @unchecked Sendable {
    private let id: String
    private let onProgress: @Sendable (Double) -> Void

    init(id: String, onProgress: @escaping @Sendable (Double) -> Void) {
        self.id = id
        self.onProgress = onProgress
    }

    func scanProgress(id: String, value: Double) {
        guard id == self.id else { return }
        onProgress(value)
    }
}

/// NSXPCConnection è thread-safe.
final class ConnectionBox: @unchecked Sendable {
    let value: NSXPCConnection
    init(_ value: NSXPCConnection) { self.value = value }
}

/// Garantisce che la continuation venga ripresa una sola volta (reply ed error handler possono arrivare entrambi).
final class ResumeOnce<T: Sendable>: @unchecked Sendable {
    private var cont: CheckedContinuation<T, Error>?
    private let lock = NSLock()

    init(_ cont: CheckedContinuation<T, Error>) { self.cont = cont }

    private func take() -> CheckedContinuation<T, Error>? {
        lock.lock(); defer { lock.unlock() }
        let c = cont
        cont = nil
        return c
    }

    func resume(returning value: T) { take()?.resume(returning: value) }
    func resume(throwing error: Error) { take()?.resume(throwing: error) }
}
