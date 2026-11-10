import Foundation

/// Constants shared by the app and the privileged helper.
public enum HelperConstants {
    public static let appIdentifier = "net.sangalli.SubnetScout"
    public static let helperIdentifier = "net.sangalli.SubnetScout.helper"
    public static let machServiceName = "net.sangalli.SubnetScout.helper"
    public static let plistName = "net.sangalli.SubnetScout.helper.plist"
    /// Bump whenever the XPC protocol changes.
    public static let protocolVersion = "4"
    /// Right required for operations that change what the helper will run as root.
    public static let adminRight = "system.privilege.admin"
}

/// Service the helper (root) exposes to the app.
///
/// The interface is deliberately narrow: the app only picks the *profile* and the
/// *targets*. The helper decides the nmap arguments, binary and data directory,
/// so a client cannot make it run arbitrary commands as root.
@objc public protocol ScanHelperProtocol {
    /// `canAdopt`: /Applications/nmap.app exists but there is no valid protected copy yet.
    func info(reply: @escaping @Sendable (_ version: String, _ nmapPath: String?, _ problem: String?, _ canAdopt: Bool) -> Void)
    /// Copies /Applications/nmap.app into a root-owned folder. Requires an administrator
    /// authorization (AuthorizationExternalForm) obtained by the app with the password.
    func adoptNmap(authorization: Data, reply: @escaping @Sendable (_ nmapPath: String?, _ error: String?) -> Void)
    /// - Parameter fullPrivileges: true = "as administrator" arguments (OS detection,
    ///   UDP, DHCP probe); false = plain scan, still run as root.
    func runScan(id: String, profile: String, targets: [String], fullPrivileges: Bool,
                 reply: @escaping @Sendable (_ xml: Data?, _ error: String?) -> Void)
    func cancelScan(id: String)
    /// ARP table and UPnP routers read by the helper (not subject to the Local Network permission).
    /// Replies with a JSON-encoded NetworkProbe.
    func networkProbe(reply: @escaping @Sendable (_ json: Data?, _ error: String?) -> Void)
}

/// Callbacks from the helper to the app (progress).
@objc public protocol ScanHelperClientProtocol {
    func scanProgress(id: String, value: Double)
}

public enum HelperInterfaces {
    public static func service() -> NSXPCInterface {
        let i = NSXPCInterface(with: ScanHelperProtocol.self)
        i.setClasses(NSSet(array: [NSArray.self, NSString.self]) as! Set<AnyHashable>,
                     for: #selector(ScanHelperProtocol.runScan(id:profile:targets:fullPrivileges:reply:)),
                     argumentIndex: 2, ofReply: false)
        return i
    }

    public static func client() -> NSXPCInterface {
        NSXPCInterface(with: ScanHelperClientProtocol.self)
    }
}

// MARK: - nmap executors

/// How nmap is run: locally (as the user or with a password) or through the helper.
public protocol NmapExecutor: Sendable {
    var isPrivileged: Bool { get }
    func execute(profile: ScanProfile, targets: [String],
                 onProgress: @escaping @Sendable (Double) -> Void) async throws -> Data
}

public struct LocalNmapExecutor: NmapExecutor {
    public let nmapPath: String
    /// true = runs as root, asking for the password (osascript).
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
