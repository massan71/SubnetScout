import Foundation

public enum NmapError: LocalizedError {
    case notInstalled
    case failed(status: Int32, stderr: String)
    case noOutput(stderr: String)
    case authorizationCancelled

    public var errorDescription: String? {
        switch self {
        case .notInstalled:
            "nmap not found. Install it with: brew install nmap"
        case .failed(let status, let stderr):
            "nmap exited with code \(status).\n\(stderr.trimmingCharacters(in: .whitespacesAndNewlines))"
        case .noOutput(let stderr):
            "nmap produced no results.\n\(stderr.trimmingCharacters(in: .whitespacesAndNewlines))"
        case .authorizationCancelled:
            "Administrator authorization cancelled."
        }
    }
}

public enum NmapLocator {
    static let candidates = ["/opt/homebrew/bin/nmap", "/usr/local/bin/nmap", "/opt/local/bin/nmap", "/usr/bin/nmap"]

    /// nmap is not bundled with the app (NPSL license): look for it in the standard paths.
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

/// Runs nmap and returns the raw XML output.
public struct NmapRunner: Sendable {
    public let nmapPath: String

    public init(nmapPath: String) {
        self.nmapPath = nmapPath
    }

    /// - Parameters:
    ///   - privileged: if true, nmap is launched as root through the standard macOS
    ///     password prompt (enables SYN scan, OS detection, UDP, MAC).
    ///   - onProgress: progress 0…1 (unprivileged mode only).
    public func run(arguments: [String], targets: [String], privileged: Bool,
                    onProgress: @escaping @Sendable (Double) -> Void = { _ in }) async throws -> Data {
        if privileged {
            return try await runPrivileged(arguments: arguments, targets: targets, onProgress: onProgress)
        }
        return try await runDirect(arguments: arguments, targets: targets, onProgress: onProgress)
    }

    // MARK: Direct execution (normal user, or inside the root helper)

    /// Runs nmap with the identity of the current process.
    /// - Parameters:
    ///   - environment: if set, replaces the inherited environment (the helper clears it).
    ///   - workingDirectory: nmap's working directory.
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

    /// Finds the last `percent="12.34"` of the <taskprogress> emitted by --stats-every.
    static func progress(in chunk: Data) -> Double? {
        let text = String(decoding: chunk, as: UTF8.self)
        guard let range = text.range(of: "percent=\"", options: .backwards) else { return nil }
        let rest = text[range.upperBound...]
        guard let end = rest.firstIndex(of: "\""), let value = Double(rest[..<end]) else { return nil }
        return min(1, max(0, value / 100))
    }

    // MARK: Administrator

    /// Without the helper: `do shell script … with administrator privileges`.
    ///
    /// nmap runs as root in the background inside a script that watches it: if
    /// the app creates the cancel file, or if the app exits (even because of a
    /// crash), the script kills nmap. So an interruption never leaves orphaned root
    /// processes. Progress is read from the XML that nmap writes as it goes.
    private func runPrivileged(arguments: [String], targets: [String],
                               onProgress: @escaping @Sendable (Double) -> Void) async throws -> Data {
        let tmp = FileManager.default.temporaryDirectory
        let id = UUID().uuidString
        let xmlURL = tmp.appending(path: "subnetscout-\(id).xml")
        let errURL = tmp.appending(path: "subnetscout-\(id).err")
        let cancelURL = tmp.appending(path: "subnetscout-\(id).cancel")
        defer {
            for url in [xmlURL, errURL, cancelURL] { try? FileManager.default.removeItem(at: url) }
        }

        let shell = Self.privilegedScript(nmapPath: nmapPath, arguments: arguments + ["--stats-every", "2s"],
                                          targets: targets, xml: xmlURL.path, err: errURL.path,
                                          cancel: cancelURL.path, appPID: getpid())
        let script = "do shell script \"\(Self.appleScriptEscape(shell))\" with administrator privileges"

        let osa = Process()
        osa.executableURL = URL(fileURLWithPath: "/usr/bin/osascript")
        osa.arguments = ["-e", script]
        let osaErr = Pipe()
        osa.standardError = osaErr
        osa.standardOutput = FileHandle.nullDevice

        // Progress: reads the tail of the XML every 2 seconds.
        let poller = Task.detached {
            while !Task.isCancelled {
                try? await Task.sleep(for: .seconds(2))
                if let tail = Self.tail(of: xmlURL, bytes: 4096), let p = Self.progress(in: tail) { onProgress(p) }
            }
        }
        defer { poller.cancel() }

        try await withTaskCancellationHandler {
            try await withCheckedThrowingContinuation { (cont: CheckedContinuation<Void, Error>) in
                osa.terminationHandler = { _ in cont.resume() }
                do { try osa.run() } catch { cont.resume(throwing: error) }
            }
        } onCancel: {
            // The root script sees the file within a second and kills nmap; osascript then exits by itself.
            FileManager.default.createFile(atPath: cancelURL.path, contents: nil)
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
        onProgress(1)
        return data
    }

    /// Shell script (one line) run as root.
    static func privilegedScript(nmapPath: String, arguments: [String], targets: [String],
                                 xml: String, err: String, cancel: String, appPID: Int32) -> String {
        let argv = [nmapPath] + arguments + ["-oX", xml, "--"] + targets
        let q = shellQuote
        return argv.map(q).joined(separator: " ") + " >/dev/null 2>\(q(err)) & NP=$!; "
            + "while kill -0 $NP 2>/dev/null; do "
            + "if [ -e \(q(cancel)) ] || ! kill -0 \(appPID) 2>/dev/null; then kill $NP 2>/dev/null; fi; "
            + "sleep 1; done; wait $NP; RC=$?; "
            + "chmod 644 \(q(xml)) \(q(err)) 2>/dev/null; "
            + "[ -e \(q(cancel)) ] && exit 0; exit $RC"
    }

    static func tail(of url: URL, bytes: Int) -> Data? {
        guard let h = try? FileHandle(forReadingFrom: url) else { return nil }
        defer { try? h.close() }
        guard let end = try? h.seekToEnd() else { return nil }
        try? h.seek(toOffset: end > UInt64(bytes) ? end - UInt64(bytes) : 0)
        return try? h.readToEnd()
    }

    static func shellQuote(_ s: String) -> String {
        "'" + s.replacingOccurrences(of: "'", with: "'\\''") + "'"
    }

    static func appleScriptEscape(_ s: String) -> String {
        s.replacingOccurrences(of: "\\", with: "\\\\").replacingOccurrences(of: "\"", with: "\\\"")
    }
}

// MARK: - Thread-safe helpers

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
