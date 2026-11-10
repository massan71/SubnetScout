import Foundation
import ServiceManagement
import ScanKit

/// State of the privileged helper as the app sees it.
enum HelperState: Equatable {
    /// First check still in progress.
    case checking
    /// The app is not running from the bundle (e.g. `swift run`): helper unavailable.
    case unavailable
    case notInstalled
    case needsApproval
    /// Registered and reachable. `problem` is set if nmap cannot safely run as root;
    /// `canAdopt` if /Applications/nmap.app can be copied to a protected location.
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
        case .connection(let m): "Cannot reach the helper: \(m)"
        case .remote(let m): m
        case .versionMismatch(let v): "Incompatible helper version (\(v)). Reinstall the helper."
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
            return .error("Unknown helper status.")
        }
    }

    /// Registers the daemon. The first time, macOS asks for approval in
    /// System Settings › General › Login Items & Extensions.
    ///
    /// If it is already registered (e.g. after a new build with a different signature, which launchd
    /// rejects with OS_REASON_CODESIGNING) it unregisters it first.
    static func install() async throws {
        if service.status == .enabled || service.status == .requiresApproval {
            try? await service.unregister()
        }
        do {
            try service.register()
        } catch {
            // "Operation not permitted" = registered but waiting for approval.
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
        // We also verify who answers on the Mach service.
        c.setCodeSigningRequirement(CodeSigning.requirement(forPeer: HelperConstants.helperIdentifier))
        c.resume()
        return c
    }

    struct Info: Sendable { var version: String; var nmapPath: String?; var problem: String?; var canAdopt: Bool }

    static func info() async throws -> Info {
        try await withTimeout(seconds: 8) { try await infoNoTimeout() }
    }

    private static func infoNoTimeout() async throws -> Info {
        let c = makeConnection()
        defer { c.invalidate() }
        let box = ConnectionBox(c)
        // Cancelling the task invalidates the connection: the error handler releases the wait.
        return try await withTaskCancellationHandler { try await withCheckedThrowingContinuation { (cont: CheckedContinuation<Info, Error>) in
            let once = ResumeOnce(cont)
            let proxy = c.remoteObjectProxyWithErrorHandler { once.resume(throwing: HelperError.connection($0.localizedDescription)) }
            guard let helper = proxy as? ScanHelperProtocol else {
                return once.resume(throwing: HelperError.connection("invalid proxy"))
            }
            helper.info { version, path, problem, canAdopt in
                once.resume(returning: Info(version: version, nmapPath: path, problem: problem, canAdopt: canAdopt))
            }
        } } onCancel: { box.value.invalidate() }
    }
}

// MARK: - Adopting nmap.app

extension HelperClient {
    /// Asks for the administrator password (system dialog) and has the helper copy
    /// /Applications/nmap.app into a root-owned folder.
    static func adoptNmap() async throws -> String {
        let auth = try await Task.detached(priority: .userInitiated) {
            try AdminAuthorization(prompt: "SubnetScout wants to copy nmap to a protected folder so it can run administrator scans without asking for your password.")
        }.value
        defer { auth.release() }

        let c = makeConnection()
        defer { c.invalidate() }
        return try await withCheckedThrowingContinuation { (cont: CheckedContinuation<String, Error>) in
            let once = ResumeOnce(cont)
            let proxy = c.remoteObjectProxyWithErrorHandler { once.resume(throwing: HelperError.connection($0.localizedDescription)) }
            guard let helper = proxy as? ScanHelperProtocol else {
                return once.resume(throwing: HelperError.connection("invalid proxy"))
            }
            helper.adoptNmap(authorization: auth.externalForm) { path, error in
                if let path { once.resume(returning: path) } else {
                    once.resume(throwing: HelperError.remote(error ?? "Copying nmap failed."))
                }
            }
        }
    }
}

// MARK: - Network probe

extension HelperClient {
    /// ARP table and UPnP routers read by the helper.
    static func networkProbe() async throws -> NetworkProbe {
        try await withTimeout(seconds: 30) { try await networkProbeNoTimeout() }
    }

    private static func networkProbeNoTimeout() async throws -> NetworkProbe {
        let c = makeConnection()
        defer { c.invalidate() }
        let box = ConnectionBox(c)
        let data = try await withTaskCancellationHandler { try await withCheckedThrowingContinuation { (cont: CheckedContinuation<Data, Error>) in
            let once = ResumeOnce(cont)
            let proxy = c.remoteObjectProxyWithErrorHandler { once.resume(throwing: HelperError.connection($0.localizedDescription)) }
            guard let helper = proxy as? ScanHelperProtocol else {
                return once.resume(throwing: HelperError.connection("invalid proxy"))
            }
            helper.networkProbe { json, error in
                if let json { once.resume(returning: json) } else {
                    once.resume(throwing: HelperError.remote(error ?? "Network probe failed."))
                }
            }
        } } onCancel: { box.value.invalidate() }
        return try JSONDecoder().decode(NetworkProbe.self, from: data)
    }
}

/// AuthorizationRef with the admin right already obtained (password entered by the user).
final class AdminAuthorization: @unchecked Sendable {
    struct Cancelled: LocalizedError {
        var errorDescription: String? { "Authorization cancelled." }
    }

    private let ref: AuthorizationRef
    let externalForm: Data

    init(prompt: String) throws {
        var ref: AuthorizationRef?
        guard AuthorizationCreate(nil, nil, [], &ref) == errAuthorizationSuccess, let ref else {
            throw HelperError.connection("AuthorizationCreate failed")
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
            throw HelperError.remote("Authorization denied (\(status)).")
        }
        var ext = AuthorizationExternalForm()
        guard AuthorizationMakeExternalForm(ref, &ext) == errAuthorizationSuccess else {
            AuthorizationFree(ref, [.destroyRights])
            throw HelperError.connection("AuthorizationMakeExternalForm failed")
        }
        self.ref = ref
        self.externalForm = withUnsafeBytes(of: &ext) { Data($0) }
    }

    /// Destroys the rights: the same authorization cannot be reused.
    func release() { AuthorizationFree(ref, [.destroyRights]) }
}

/// Runs scans through the root helper: no password, with progress.
struct HelperNmapExecutor: NmapExecutor {
    /// "As administrator" arguments; nmap runs as root in the helper anyway.
    var fullPrivileges: Bool
    var isPrivileged: Bool { fullPrivileges }

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
                        return once.resume(throwing: HelperError.connection("invalid proxy"))
                    }
                    helper.runScan(id: id, profile: profile.rawValue, targets: targets, fullPrivileges: fullPrivileges) { data, error in
                        if let data {
                            once.resume(returning: data)
                        } else {
                            once.resume(throwing: HelperError.remote(error ?? "Unknown helper error."))
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

// MARK: - Concurrency helpers

struct HelperTimeout: LocalizedError {
    var errorDescription: String? {
        "The helper is not responding. If you just updated SubnetScout, click “Reinstall” and approve it again."
    }
}

/// Runs `operation` with a time limit: an XPC connection to a helper that
/// macOS does not let start would otherwise wait forever.
func withTimeout<T: Sendable>(seconds: Double, _ operation: @escaping @Sendable () async throws -> T) async throws -> T {
    try await withThrowingTaskGroup(of: T.self) { group in
        group.addTask { try await operation() }
        group.addTask {
            try await Task.sleep(for: .seconds(seconds))
            throw HelperTimeout()
        }
        defer { group.cancelAll() }
        return try await group.next()!
    }
}

/// Receives progress from the helper (called on an XPC queue).
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

/// NSXPCConnection is thread-safe.
final class ConnectionBox: @unchecked Sendable {
    let value: NSXPCConnection
    init(_ value: NSXPCConnection) { self.value = value }
}

/// Ensures the continuation is resumed only once (reply and error handler can both arrive).
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
