import Foundation

/// Costanti condivise tra app e privileged helper.
public enum HelperConstants {
    public static let appIdentifier = "net.sangalli.SubnetScout"
    public static let helperIdentifier = "net.sangalli.SubnetScout.helper"
    public static let machServiceName = "net.sangalli.SubnetScout.helper"
    public static let plistName = "net.sangalli.SubnetScout.helper.plist"
    /// Da incrementare quando cambia il protocollo XPC.
    public static let protocolVersion = "3"
    /// Diritto richiesto per operazioni che cambiano cosa il helper eseguirà come root.
    public static let adminRight = "system.privilege.admin"
}

/// Servizio esposto dal helper (root) all'app.
///
/// L'interfaccia è volutamente ristretta: l'app sceglie solo il *profilo* e i
/// *target*. Argomenti di nmap, binario e directory dati li decide il helper,
/// così un client non può fargli eseguire comandi arbitrari come root.
@objc public protocol ScanHelperProtocol {
    /// `canAdopt`: esiste /Applications/nmap.app ma non ancora una copia protetta valida.
    func info(reply: @escaping @Sendable (_ version: String, _ nmapPath: String?, _ problem: String?, _ canAdopt: Bool) -> Void)
    /// Copia /Applications/nmap.app in una cartella di root. Richiede un'autorizzazione
    /// amministratore (AuthorizationExternalForm) ottenuta dall'app con la password.
    func adoptNmap(authorization: Data, reply: @escaping @Sendable (_ nmapPath: String?, _ error: String?) -> Void)
    func runScan(id: String, profile: String, targets: [String],
                 reply: @escaping @Sendable (_ xml: Data?, _ error: String?) -> Void)
    func cancelScan(id: String)
    /// Tabella ARP e router UPnP letti dal helper (non soggetto al permesso «Rete locale»).
    /// Risponde con un NetworkProbe codificato in JSON.
    func networkProbe(reply: @escaping @Sendable (_ json: Data?, _ error: String?) -> Void)
}

/// Callback dal helper verso l'app (avanzamento).
@objc public protocol ScanHelperClientProtocol {
    func scanProgress(id: String, value: Double)
}

public enum HelperInterfaces {
    public static func service() -> NSXPCInterface {
        let i = NSXPCInterface(with: ScanHelperProtocol.self)
        i.setClasses(NSSet(array: [NSArray.self, NSString.self]) as! Set<AnyHashable>,
                     for: #selector(ScanHelperProtocol.runScan(id:profile:targets:reply:)),
                     argumentIndex: 2, ofReply: false)
        return i
    }

    public static func client() -> NSXPCInterface {
        NSXPCInterface(with: ScanHelperClientProtocol.self)
    }
}

// MARK: - Esecutori di nmap

/// Strategia di esecuzione di nmap: locale (utente o password) oppure tramite helper.
public protocol NmapExecutor: Sendable {
    var isPrivileged: Bool { get }
    func execute(profile: ScanProfile, targets: [String],
                 onProgress: @escaping @Sendable (Double) -> Void) async throws -> Data
}

public struct LocalNmapExecutor: NmapExecutor {
    public let nmapPath: String
    /// true = esegue come root chiedendo la password (osascript).
    public let askPassword: Bool

    public init(nmapPath: String, askPassword: Bool) {
        self.nmapPath = nmapPath
        self.askPassword = askPassword
    }

    public var isPrivileged: Bool { askPassword }

    public func execute(profile: ScanProfile, targets: [String],
                        onProgress: @escaping @Sendable (Double) -> Void) async throws -> Data {
        try await NmapRunner(nmapPath: nmapPath).run(arguments: profile.arguments(privileged: askPassword),
                                                     targets: targets, privileged: askPassword,
                                                     onProgress: onProgress)
    }
}
