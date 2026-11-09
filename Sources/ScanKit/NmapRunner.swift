import Foundation

public enum NmapError: LocalizedError {
    case notInstalled
    case failed(status: Int32, stderr: String)
    case noOutput(stderr: String)
    case authorizationCancelled

    public var errorDescription: String? {
        switch self {
        case .notInstalled:
            "nmap non trovato. Installalo con: brew install nmap"
        case .failed(let status, let stderr):
            "nmap è terminato con codice \(status).\n\(stderr.trimmingCharacters(in: .whitespacesAndNewlines))"
        case .noOutput(let stderr):
            "nmap non ha prodotto risultati.\n\(stderr.trimmingCharacters(in: .whitespacesAndNewlines))"
        case .authorizationCancelled:
            "Autorizzazione amministratore annullata."
        }
    }
}

public enum NmapLocator {
    static let candidates = ["/opt/homebrew/bin/nmap", "/usr/local/bin/nmap", "/opt/local/bin/nmap", "/usr/bin/nmap"]

    /// nmap non viene incluso nell'app (licenza NPSL): lo si cerca nei percorsi standard.
    public static func find() -> String? {
        candidates.first { FileManager.default.isExecutableFile(atPath: $0) }
    }

    public static func version(at path: String) -> String? {
        guard let out = try? Shell.run(path, ["--version"]) else { return nil }
        // "Nmap version 7.95 ( https://nmap.org )"
        let first = out.split(separator: "\n").first.map(String.init) ?? ""
        return first.components(separatedBy: "version ").last?
            .components(separatedBy: " ").first
    }
}

/// Esegue nmap e restituisce l'output XML grezzo.
public struct NmapRunner: Sendable {
    public let nmapPath: String

    public init(nmapPath: String) {
        self.nmapPath = nmapPath
    }

    /// - Parameters:
    ///   - privileged: se true, nmap viene lanciato come root tramite la richiesta
    ///     password standard di macOS (abilita SYN scan, OS detection, UDP, MAC).
    ///   - onProgress: avanzamento 0…1 (solo in modalità non privilegiata).
    public func run(arguments: [String], targets: [String], privileged: Bool,
                    onProgress: @escaping @Sendable (Double) -> Void = { _ in }) async throws -> Data {
        if privileged {
            return try await runPrivileged(arguments: arguments, targets: targets)
        }
        return try await runDirect(arguments: arguments, targets: targets, onProgress: onProgress)
    }

    // MARK: Esecuzione diretta (utente normale, oppure dentro il helper root)

    /// Esegue nmap con l'identità del processo corrente.
    /// - Parameters:
    ///   - environment: se valorizzato sostituisce l'ambiente ereditato (il helper lo azzera).
    ///   - workingDirectory: directory di lavoro di nmap.
    public func runDirect(arguments: [String], targets: [String],
                          environment: [String: String]? = nil, workingDirectory: URL? = nil,
                          onProgress: @escaping @Sendable (Double) -> Void) async throws -> Data {
        let process = Process()
        process.executableURL = URL(fileURLWithPath: nmapPath)
        process.arguments = arguments + ["--stats-every", "2s", "-oX", "-", "--"] + targets
        if let environment { process.environment = environment }
        if let workingDirectory { process.currentDirectoryURL = workingDirectory }
        let out = Pipe(), err = Pipe()
        process.standardOutput = out
        process.standardError = err

        let box = ProcessBox(process)
        let stdout = DataBuffer(), stderr = DataBuffer()

        try await withTaskCancellationHandler {
            try await withCheckedThrowingContinuation { (cont: CheckedContinuation<Void, Error>) in
                let group = DispatchGroup()
                group.enter(); group.enter(); group.enter()

                DispatchQueue.global(qos: .userInitiated).async {
                    let h = out.fileHandleForReading
                    while let chunk = try? h.read(upToCount: 64 * 1024), !chunk.isEmpty {
                        stdout.append(chunk)
                        if let p = Self.progress(in: chunk) { onProgress(p) }
                    }
                    group.leave()
                }
                DispatchQueue.global(qos: .utility).async {
                    let h = err.fileHandleForReading
                    while let chunk = try? h.read(upToCount: 16 * 1024), !chunk.isEmpty {
                        stderr.append(chunk)
                    }
                    group.leave()
                }
                process.terminationHandler = { _ in group.leave() }

                do {
                    try process.run()
                } catch {
                    cont.resume(throwing: error)
                    return
                }
                group.notify(queue: .global()) { cont.resume() }
            }
        } onCancel: {
            box.terminate()
        }

        try Task.checkCancellation()
        let data = stdout.data
        let errText = String(decoding: stderr.data, as: UTF8.self)
        guard !data.isEmpty else {
            throw process.terminationStatus == 0 ? NmapError.noOutput(stderr: errText)
                                                 : NmapError.failed(status: process.terminationStatus, stderr: errText)
        }
        onProgress(1)
        return data
    }

    /// Cerca l'ultimo `percent="12.34"` dei <taskprogress> emessi da --stats-every.
    static func progress(in chunk: Data) -> Double? {
        let text = String(decoding: chunk, as: UTF8.self)
        guard let range = text.range(of: "percent=\"", options: .backwards) else { return nil }
        let rest = text[range.upperBound...]
        guard let end = rest.firstIndex(of: "\""), let value = Double(rest[..<end]) else { return nil }
        return min(1, max(0, value / 100))
    }

    // MARK: Amministratore

    /// MVP: usa `do shell script … with administrator privileges`. Per un'app da
    /// distribuire andrà sostituito da un privileged helper (SMAppService + XPC).
    private func runPrivileged(arguments: [String], targets: [String]) async throws -> Data {
        let tmp = FileManager.default.temporaryDirectory
        let xmlURL = tmp.appending(path: "subnetscout-\(UUID().uuidString).xml")
        let errURL = tmp.appending(path: "subnetscout-\(UUID().uuidString).err")
        defer {
            try? FileManager.default.removeItem(at: xmlURL)
            try? FileManager.default.removeItem(at: errURL)
        }

        let argv = [nmapPath] + arguments + ["-oX", xmlURL.path, "--"] + targets
        let shell = argv.map(Self.shellQuote).joined(separator: " ")
            + " >/dev/null 2>" + Self.shellQuote(errURL.path)
            + "; chmod 644 " + Self.shellQuote(xmlURL.path) + " " + Self.shellQuote(errURL.path)
        let script = "do shell script \"\(Self.appleScriptEscape(shell))\" with administrator privileges"

        let osa = Process()
        osa.executableURL = URL(fileURLWithPath: "/usr/bin/osascript")
        osa.arguments = ["-e", script]
        let osaErr = Pipe()
        osa.standardError = osaErr
        osa.standardOutput = FileHandle.nullDevice
        let box = ProcessBox(osa)

        try await withTaskCancellationHandler {
            try await withCheckedThrowingContinuation { (cont: CheckedContinuation<Void, Error>) in
                osa.terminationHandler = { _ in cont.resume() }
                do { try osa.run() } catch { cont.resume(throwing: error) }
            }
        } onCancel: {
            // Nota: termina osascript; il processo nmap root può proseguire fino alla fine.
            box.terminate()
        }
        try Task.checkCancellation()

        let osaMessage = String(decoding: osaErr.fileHandleForReading.readDataToEndOfFile(), as: UTF8.self)
        if osa.terminationStatus != 0 {
            if osaMessage.contains("-128") { throw NmapError.authorizationCancelled }
            throw NmapError.failed(status: osa.terminationStatus, stderr: osaMessage)
        }
        let data = (try? Data(contentsOf: xmlURL)) ?? Data()
        guard !data.isEmpty else {
            let errText = (try? String(contentsOf: errURL, encoding: .utf8)) ?? osaMessage
            throw NmapError.noOutput(stderr: errText)
        }
        return data
    }

    static func shellQuote(_ s: String) -> String {
        "'" + s.replacingOccurrences(of: "'", with: "'\\''") + "'"
    }

    static func appleScriptEscape(_ s: String) -> String {
        s.replacingOccurrences(of: "\\", with: "\\\\").replacingOccurrences(of: "\"", with: "\\\"")
    }
}

// MARK: - Helper thread-safe

private final class ProcessBox: @unchecked Sendable {
    private let process: Process
    init(_ p: Process) { process = p }
    func terminate() { if process.isRunning { process.terminate() } }
}

private final class DataBuffer: @unchecked Sendable {
    private var storage = Data()
    private let lock = NSLock()
    func append(_ d: Data) { lock.lock(); storage.append(d); lock.unlock() }
    var data: Data { lock.lock(); defer { lock.unlock() }; return storage }
}
