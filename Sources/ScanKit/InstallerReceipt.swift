import Foundation

/// Compares a copy of nmap.app with the receipt of the official installer
/// (`/var/db/receipts/org.insecure.nmap.bom`, written by macOS at install time).
///
/// The receipt holds the size and POSIX `cksum` checksum (CRC-32) of every file:
/// it catches accidental or trivial changes made after installation, not an
/// attacker determined to forge a CRC. It is an extra check, not a signature.
public enum InstallerReceipt {
    public struct Entry: Equatable, Sendable {
        public var size: Int
        public var cksum: UInt32
    }

    public enum Mismatch: LocalizedError, Equatable {
        case receiptMissing
        case modified(String)
        case unexpected(String)
        case missing(String)

        public var errorDescription: String? {
            switch self {
            case .receiptMissing:
                "nmap installer receipt not found: reinstall nmap with the official package from nmap.org."
            case .modified(let f):
                "nmap.app was modified after installation (“\(f)”): reinstall it from the official package before using it as root."
            case .unexpected(let f):
                "nmap.app contains a file the installer did not install (“\(f)”): reinstall it from the official package."
            case .missing(let f):
                "A file of nmap.app is missing (“\(f)”): reinstall it from the official package."
            }
        }
    }

    public static let receiptBOM = "/var/db/receipts/org.insecure.nmap.bom"
    public static let bomPrefix = "./nmap.app/Contents/Resources/"

    /// Lines of `lsbom -p fMsc`: "./path<TAB>-rwxr-xr-x<TAB>size<TAB>cksum".
    /// Returns only the regular files under `prefix`, with relative paths.
    static func parseBOM(_ listing: String, prefix: String) -> [String: Entry] {
        var out: [String: Entry] = [:]
        for line in listing.split(separator: "\n") {
            let f = line.split(separator: "\t", omittingEmptySubsequences: false)
            guard f.count >= 4, f[0].hasPrefix(prefix), f[1].hasPrefix("-"),
                  let size = Int(f[2]), let ck = UInt32(f[3].trimmingCharacters(in: .whitespaces)) else { continue }
            out[String(f[0].dropFirst(prefix.count))] = Entry(size: size, cksum: ck)
        }
        return out
    }

    /// Output of `cksum file…`: "crc size path".
    static func parseCksum(_ output: String, root: String) -> [String: Entry] {
        var out: [String: Entry] = [:]
        let base = root.hasSuffix("/") ? root : root + "/"
        for line in output.split(separator: "\n") {
            let f = line.split(separator: " ", maxSplits: 2)
            guard f.count == 3, let ck = UInt32(f[0]), let size = Int(f[1]), f[2].hasPrefix(base) else { continue }
            out[String(f[2].dropFirst(base.count))] = Entry(size: size, cksum: ck)
        }
        return out
    }

    /// Compares the regular files of `root` (bin, lib, share) with the receipt.
    public static func verify(root: String, receipt: String = receiptBOM, prefix: String = bomPrefix) throws {
        guard FileManager.default.fileExists(atPath: receipt),
              let listing = try? Shell.run("/usr/bin/lsbom", ["-p", "fMsc", receipt]) else {
            throw Mismatch.receiptMissing
        }
        let expected = parseBOM(listing, prefix: prefix)
            .filter { entry in ["bin/", "lib/", "share/"].contains { entry.key.hasPrefix($0) } }
        guard !expected.isEmpty else { throw Mismatch.receiptMissing }

        var files: [String] = []
        let base = root.hasSuffix("/") ? String(root.dropLast()) : root
        if let walker = FileManager.default.enumerator(atPath: base) {
            for case let rel as String in walker {
                var st = stat()
                let full = base + "/" + rel
                if lstat(full, &st) == 0, st.st_mode & S_IFMT == S_IFREG { files.append(full) }
            }
        }
        var actual: [String: Entry] = [:]
        for chunk in stride(from: 0, to: files.count, by: 400).map({ Array(files[$0..<min($0 + 400, files.count)]) }) {
            actual.merge(parseCksum((try? Shell.run("/usr/bin/cksum", chunk)) ?? "", root: base)) { a, _ in a }
        }
        try compare(expected: expected, actual: actual)
    }

    static func compare(expected: [String: Entry], actual: [String: Entry]) throws {
        for (path, entry) in actual.sorted(by: { $0.key < $1.key }) {
            guard let want = expected[path] else { throw Mismatch.unexpected(path) }
            guard want == entry else { throw Mismatch.modified(path) }
        }
        if let missing = expected.keys.sorted().first(where: { actual[$0] == nil }) {
            throw Mismatch.missing(missing)
        }
    }
}
