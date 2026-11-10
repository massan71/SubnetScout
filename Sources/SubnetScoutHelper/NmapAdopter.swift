import Foundation
import Security
import Darwin
import ScanKit

/// Crea la copia protetta di nmap.app in `TrustedNmap.adoptedRoot` (tutto root:wheel, niente
/// permessi di scrittura per gruppo/altri). Il sorgente è fisso: il client non sceglie percorsi.
enum NmapAdopter {
    enum AdoptError: LocalizedError {
        case unauthorized
        case sourceMissing
        case escapingSymlink(String)

        var errorDescription: String? {
            switch self {
            case .unauthorized: "Autorizzazione amministratore non valida o scaduta."
            case .sourceMissing: "/Applications/nmap.app non trovato. Installa nmap dal pacchetto di nmap.org."
            case .escapingSymlink(let p): "Link simbolico non consentito in nmap.app: \(p)"
            }
        }
    }

    /// Verifica che il client abbia ottenuto il diritto admin (password) su questa AuthorizationRef.
    static func verifyAdmin(_ data: Data) -> Bool {
        guard data.count == MemoryLayout<AuthorizationExternalForm>.size else { return false }
        var ext = AuthorizationExternalForm()
        withUnsafeMutableBytes(of: &ext) { _ = data.copyBytes(to: $0) }
        var ref: AuthorizationRef?
        guard AuthorizationCreateFromExternalForm(&ext, &ref) == errAuthorizationSuccess, let ref else { return false }
        defer { AuthorizationFree(ref, []) }

        var status = errAuthorizationDenied
        HelperConstants.adminRight.withCString { name in
            var item = AuthorizationItem(name: name, valueLength: 0, value: nil, flags: 0)
            withUnsafeMutablePointer(to: &item) { ptr in
                var rights = AuthorizationRights(count: 1, items: ptr)
                // Nessuna interazione: passa solo se il client ha già inserito la password.
                status = AuthorizationCopyRights(ref, &rights, nil, [.extendRights], nil)
            }
        }
        return status == errAuthorizationSuccess
    }

    static func adopt() throws -> TrustedNmap.Resolved {
        let fm = FileManager.default
        let source = URL(fileURLWithPath: TrustedNmap.adoptionSource)
        guard fm.isExecutableFile(atPath: source.appending(path: "bin/nmap").path) else { throw AdoptError.sourceMissing }

        let root = URL(fileURLWithPath: TrustedNmap.adoptedRoot)
        let parent = root.deletingLastPathComponent()
        try fm.createDirectory(at: parent, withIntermediateDirectories: true)
        try harden(parent.path, isDirectory: true)

        let staging = parent.appending(path: ".nmap-staging-\(UUID().uuidString)")
        defer { try? fm.removeItem(at: staging) }
        try fm.createDirectory(at: staging, withIntermediateDirectories: false)
        try harden(staging.path, isDirectory: true)

        for sub in ["bin", "lib", "share"] {
            let src = source.appending(path: sub)
            if fm.fileExists(atPath: src.path) {
                try fm.copyItem(at: src, to: staging.appending(path: sub))
            }
        }
        try hardenTree(staging)
        // La copia ora è di root (non più modificabile dall'utente): la si confronta
        // con la ricevuta dell'installer prima di renderla attiva.
        try InstallerReceipt.verify(root: staging.path)

        // Sostituzione atomica della copia precedente.
        let old = parent.appending(path: ".nmap-old-\(UUID().uuidString)")
        if fm.fileExists(atPath: root.path) { try fm.moveItem(at: root, to: old) }
        try fm.moveItem(at: staging, to: root)
        try? fm.removeItem(at: old)

        return try TrustedNmap.check(root.appending(path: "bin/nmap").path)
    }

    /// root:wheel e niente scrittura per gruppo/altri su ogni elemento; i link simbolici
    /// devono puntare dentro la copia.
    private static func hardenTree(_ dir: URL) throws {
        let base = dir.resolvingSymlinksInPath().path
        guard let walker = FileManager.default.enumerator(atPath: dir.path) else { return }
        for case let rel as String in walker {
            let p = dir.path + "/" + rel
            var st = stat()
            guard lstat(p, &st) == 0 else { continue }
            if st.st_mode & S_IFMT == S_IFLNK {
                let target = URL(fileURLWithPath: p).resolvingSymlinksInPath().path
                guard target.hasPrefix(base + "/") else { throw AdoptError.escapingSymlink(rel) }
                lchown(p, 0, 0)
            } else {
                try harden(p, isDirectory: st.st_mode & S_IFMT == S_IFDIR)
            }
        }
    }

    private static func harden(_ path: String, isDirectory: Bool) throws {
        var st = stat()
        guard lstat(path, &st) == 0 else { throw CocoaError(.fileNoSuchFile) }
        guard lchown(path, 0, 0) == 0 else { throw POSIXError(.EPERM) }
        let mode = (st.st_mode & 0o7777) & ~mode_t(0o7022) // niente setuid/setgid/sticky, niente g+w/o+w
        guard chmod(path, isDirectory ? (mode | 0o755) : mode) == 0 else { throw POSIXError(.EPERM) }
    }
}
