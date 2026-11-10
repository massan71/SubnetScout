import Foundation

/// Confronta una copia di nmap.app con la ricevuta dell'installer ufficiale
/// (`/var/db/receipts/org.insecure.nmap.bom`, scritta da macOS all'installazione).
///
/// La ricevuta contiene dimensione e checksum POSIX `cksum` (CRC-32) di ogni file:
/// intercetta modifiche accidentali o banali fatte dopo l'installazione, non un
/// attaccante deciso a falsificare un CRC. È un controllo in più, non una firma.
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
                "Ricevuta dell'installer di nmap non trovata: reinstalla nmap con il pacchetto ufficiale di nmap.org."
            case .modified(let f):
                "nmap.app è stato modificato dopo l'installazione («\(f)»): reinstallalo dal pacchetto ufficiale prima di usarlo come root."
            case .unexpected(let f):
                "nmap.app contiene un file non previsto dall'installer («\(f)»): reinstallalo dal pacchetto ufficiale."
            case .missing(let f):
                "Manca un file di nmap.app («\(f)»): reinstallalo dal pacchetto ufficiale."
            }
        }
    }

    public static let receiptBOM = "/var/db/receipts/org.insecure.nmap.bom"
    public static let bomPrefix = "./nmap.app/Contents/Resources/"

    /// Righe di `lsbom -p fMsc`: "./percorso<TAB>-rwxr-xr-x<TAB>size<TAB>cksum".
    /// Restituisce solo i file regolari sotto `prefix`, con percorso relativo.
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

    /// Output di `cksum file…`: "crc size percorso".
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

    /// Confronta i file regolari di `root` (bin, lib, share) con la ricevuta.
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
