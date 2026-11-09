import Foundation

/// Storico delle scansioni: un file JSON per scansione in
/// ~/Library/Application Support/SubnetScout/Scans.
public struct ScanHistoryStore: Sendable {
    public let directory: URL

    public init(directory: URL? = nil) {
        if let directory {
            self.directory = directory
        } else {
            let base = FileManager.default.urls(for: .applicationSupportDirectory, in: .userDomainMask)[0]
            self.directory = base.appending(path: "SubnetScout/Scans", directoryHint: .isDirectory)
        }
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
        try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: true)
        let data = try Self.encoder().encode(result)
        try data.write(to: url(for: result.id), options: .atomic)
    }

    public func loadAll() -> [ScanResult] {
        let files = (try? FileManager.default.contentsOfDirectory(at: directory, includingPropertiesForKeys: nil)) ?? []
        let decoder = Self.decoder()
        return files.filter { $0.pathExtension == "json" }
            .compactMap { try? decoder.decode(ScanResult.self, from: Data(contentsOf: $0)) }
            .sorted { $0.finishedAt > $1.finishedAt }
    }

    public func delete(_ id: UUID) {
        try? FileManager.default.removeItem(at: url(for: id))
    }

    /// Scansione precedente dello stesso target, per calcolare il diff.
    public func previous(of result: ScanResult, in history: [ScanResult]) -> ScanResult? {
        history.filter { $0.id != result.id && $0.target == result.target && $0.finishedAt < result.finishedAt }
            .max { $0.finishedAt < $1.finishedAt }
    }

    private func url(for id: UUID) -> URL {
        directory.appending(path: "\(id.uuidString).json")
    }
}
