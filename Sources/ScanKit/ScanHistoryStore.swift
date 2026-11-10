import Foundation
import CryptoKit
import Security

/// Scan history in ~/Library/Application Support/SubnetScout/Scans.
///
/// Every scan contains the network inventory with vulnerabilities and CVEs, so
/// it is encrypted with AES-256-GCM (`.ssenc` files). The key is random and lives in
/// the Keychain (this Mac only); folder 0700, files 0600. Plaintext scans from
/// earlier versions (`.json`) are encrypted on first load.
public struct ScanHistoryStore: Sendable {
    public let directory: URL
    private let keyProvider: @Sendable () throws -> SymmetricKey

    static let magic = Data("SSv1".utf8)
    static let fileExtension = "ssenc"

    public enum StoreError: LocalizedError {
        case unreadable(String)

        public var errorDescription: String? {
            switch self {
            case .unreadable(let name): "Cannot decrypt scan \(name) (Keychain key missing or different)."
            }
        }
    }

    /// - Parameters:
    ///   - directory: history folder (default Application Support).
    ///   - keyProvider: encryption key; the Keychain one by default.
    public init(directory: URL? = nil, keyProvider: (@Sendable () throws -> SymmetricKey)? = nil) {
        if let directory {
            self.directory = directory
        } else {
            let base = FileManager.default.urls(for: .applicationSupportDirectory, in: .userDomainMask)[0]
            self.directory = base.appending(path: "SubnetScout/Scans", directoryHint: .isDirectory)
        }
        self.keyProvider = keyProvider ?? { try HistoryKey.cached() }
    }

    public static func encoder() -> JSONEncoder {
        let e = JSONEncoder()
        e.dateEncodingStrategy = .iso8601
        e.outputFormatting = [.prettyPrinted, .sortedKeys]
        return e
    }

    public static func decoder() -> JSONDecoder {
        let d = JSONDecoder()
        d.dateDecodingStrategy = .iso8601
        return d
    }

    public func save(_ result: ScanResult) throws {
        try prepareDirectory()
        let plain = try Self.encoder().encode(result)
        let sealed = try AES.GCM.seal(plain, using: keyProvider()).combined!
        let url = url(for: result.id)
        try (Self.magic + sealed).write(to: url, options: [.atomic])
        try FileManager.default.setAttributes([.posixPermissions: 0o600], ofItemAtPath: url.path)
    }

    /// All readable scans, newest first. Migrates the plaintext ones.
    public func loadAll() -> [ScanResult] {
        let files = (try? FileManager.default.contentsOfDirectory(at: directory, includingPropertiesForKeys: nil)) ?? []
        try? prepareDirectory()
        var results: [ScanResult] = []
        for file in files {
            switch file.pathExtension {
            case Self.fileExtension:
                if let r = try? decrypt(file) { results.append(r) }
            case "json":
                // Plaintext scan from an earlier version: encrypt it and delete the original.
                guard let data = try? Data(contentsOf: file),
                      let r = try? Self.decoder().decode(ScanResult.self, from: data) else { continue }
                if (try? save(r)) != nil, (try? decrypt(url(for: r.id))) != nil {
                    try? FileManager.default.removeItem(at: file)
                }
                results.append(r)
            default:
                continue
            }
        }
        return results.sorted { $0.finishedAt > $1.finishedAt }
    }

    /// Like `loadAll()`, plus the number of files that could not be decrypted, in a single pass.
    public func loadAllReportingUnreadable() -> (results: [ScanResult], unreadable: Int) {
        let results = loadAll()
        let files = (try? FileManager.default.contentsOfDirectory(at: directory, includingPropertiesForKeys: nil)) ?? []
        let encrypted = files.filter { $0.pathExtension == Self.fileExtension }.count
        return (results, max(0, encrypted - results.count))
    }

    /// Number of files that could not be decrypted (e.g. key deleted).
    public func unreadableCount() -> Int {
        let files = (try? FileManager.default.contentsOfDirectory(at: directory, includingPropertiesForKeys: nil)) ?? []
        return files.filter { $0.pathExtension == Self.fileExtension && (try? decrypt($0)) == nil }.count
    }

    func decrypt(_ file: URL) throws -> ScanResult {
        let data = try Data(contentsOf: file)
        guard data.starts(with: Self.magic) else { throw StoreError.unreadable(file.lastPathComponent) }
        do {
            let box = try AES.GCM.SealedBox(combined: data.dropFirst(Self.magic.count))
            let plain = try AES.GCM.open(box, using: keyProvider())
            return try Self.decoder().decode(ScanResult.self, from: plain)
        } catch {
            throw StoreError.unreadable(file.lastPathComponent)
        }
    }

    public func delete(_ id: UUID) {
        try? FileManager.default.removeItem(at: url(for: id))
        try? FileManager.default.removeItem(at: directory.appending(path: "\(id.uuidString).json"))
    }

    /// Previous scan of the same target, to compute the diff.
    public func previous(of result: ScanResult, in history: [ScanResult]) -> ScanResult? {
        history.filter { $0.id != result.id && $0.target == result.target && $0.finishedAt < result.finishedAt }
            .max { $0.finishedAt < $1.finishedAt }
    }

    private func prepareDirectory() throws {
        try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: true)
        try FileManager.default.setAttributes([.posixPermissions: 0o700], ofItemAtPath: directory.path)
    }

    private func url(for id: UUID) -> URL {
        directory.appending(path: "\(id.uuidString).\(Self.fileExtension)")
    }
}

/// AES-256 key of the history in the login Keychain (this Mac only).
public enum HistoryKey {
    static let service = "net.sangalli.SubnetScout.history-key"

    public enum KeyError: LocalizedError {
        case keychain(OSStatus)
        public var errorDescription: String? {
            switch self {
            case .keychain(let s): "Keychain not accessible (\(s))."
            }
        }
    }

    private static let lock = NSLock()
    nonisolated(unsafe) private static var memo: SymmetricKey?

    /// Like `load()`, but reads the Keychain only once per process.
    public static func cached() throws -> SymmetricKey {
        lock.lock(); defer { lock.unlock() }
        if let memo { return memo }
        let key = try load()
        memo = key
        return key
    }

    /// Returns the key, creating it the first time.
    public static func load() throws -> SymmetricKey {
        let query: [String: Any] = [kSecClass as String: kSecClassGenericPassword,
                                    kSecAttrService as String: service,
                                    kSecReturnData as String: true,
                                    kSecMatchLimit as String: kSecMatchLimitOne]
        var item: CFTypeRef?
        let status = SecItemCopyMatching(query as CFDictionary, &item)
        if status == errSecSuccess, let data = item as? Data, data.count == 32 {
            return SymmetricKey(data: data)
        }
        guard status == errSecItemNotFound else { throw KeyError.keychain(status) }
        let key = SymmetricKey(size: .bits256)
        let add: [String: Any] = [kSecClass as String: kSecClassGenericPassword,
                                  kSecAttrService as String: service,
                                  kSecAttrLabel as String: "SubnetScout – history key",
                                  kSecAttrAccessible as String: kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly,
                                  kSecValueData as String: key.withUnsafeBytes { Data($0) }]
        let addStatus = SecItemAdd(add as CFDictionary, nil)
        guard addStatus == errSecSuccess else { throw KeyError.keychain(addStatus) }
        return key
    }
}
