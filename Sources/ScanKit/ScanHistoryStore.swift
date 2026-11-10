import Foundation
import CryptoKit
import Security

/// Storico delle scansioni in ~/Library/Application Support/SubnetScout/Scans.
///
/// Ogni scansione contiene l'inventario della rete con vulnerabilità e CVE, quindi
/// viene cifrata con AES-256-GCM (file `.ssenc`). La chiave è casuale e sta nel
/// Portachiavi (solo su questo Mac); cartella 0700, file 0600. Le scansioni in chiaro
/// delle versioni precedenti (`.json`) vengono cifrate al primo caricamento.
public struct ScanHistoryStore: Sendable {
    public let directory: URL
    private let keyProvider: @Sendable () throws -> SymmetricKey

    static let magic = Data("SSv1".utf8)
    static let fileExtension = "ssenc"

    public enum StoreError: LocalizedError {
        case unreadable(String)

        public var errorDescription: String? {
            switch self {
            case .unreadable(let name): "Impossibile decifrare la scansione \(name) (chiave del Portachiavi mancante o diversa)."
            }
        }
    }

    /// - Parameters:
    ///   - directory: cartella dello storico (default Application Support).
    ///   - keyProvider: chiave di cifratura; di default quella del Portachiavi.
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

    /// Tutte le scansioni leggibili, dalla più recente. Migra quelle in chiaro.
    public func loadAll() -> [ScanResult] {
        let files = (try? FileManager.default.contentsOfDirectory(at: directory, includingPropertiesForKeys: nil)) ?? []
        try? prepareDirectory()
        var results: [ScanResult] = []
        for file in files {
            switch file.pathExtension {
            case Self.fileExtension:
                if let r = try? decrypt(file) { results.append(r) }
            case "json":
                // Scansione in chiaro di una versione precedente: cifrala ed elimina l'originale.
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

    /// Come `loadAll()`, più il numero di file non decifrabili, in un solo passaggio.
    public func loadAllReportingUnreadable() -> (results: [ScanResult], unreadable: Int) {
        let results = loadAll()
        let files = (try? FileManager.default.contentsOfDirectory(at: directory, includingPropertiesForKeys: nil)) ?? []
        let encrypted = files.filter { $0.pathExtension == Self.fileExtension }.count
        return (results, max(0, encrypted - results.count))
    }

    /// Numero di file che non è stato possibile decifrare (es. chiave cancellata).
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

    /// Scansione precedente dello stesso target, per calcolare il diff.
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

/// Chiave AES-256 dello storico nel Portachiavi di login (solo questo Mac).
public enum HistoryKey {
    static let service = "net.sangalli.SubnetScout.history-key"

    public enum KeyError: LocalizedError {
        case keychain(OSStatus)
        public var errorDescription: String? {
            switch self {
            case .keychain(let s): "Portachiavi non accessibile (\(s))."
            }
        }
    }

    private static let lock = NSLock()
    nonisolated(unsafe) private static var memo: SymmetricKey?

    /// Come `load()`, ma legge il Portachiavi una sola volta per processo.
    public static func cached() throws -> SymmetricKey {
        lock.lock(); defer { lock.unlock() }
        if let memo { return memo }
        let key = try load()
        memo = key
        return key
    }

    /// Restituisce la chiave, creandola la prima volta.
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
                                  kSecAttrLabel as String: "SubnetScout – chiave dello storico",
                                  kSecAttrAccessible as String: kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly,
                                  kSecValueData as String: key.withUnsafeBytes { Data($0) }]
        let addStatus = SecItemAdd(add as CFDictionary, nil)
        guard addStatus == errSecSuccess else { throw KeyError.keychain(addStatus) }
        return key
    }
}
