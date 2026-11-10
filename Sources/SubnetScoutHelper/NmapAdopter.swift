import Foundation
import Security
import Darwin
import ScanKit

/// Creates the protected copy of nmap.app in `TrustedNmap.adoptedRoot` (all root:wheel, no
/// group/other write permissions). The source is fixed: the client does not choose paths.
enum NmapAdopter {
    enum AdoptError: LocalizedError {
        case unauthorized
        case sourceMissing
        case escapingSymlink(String)

        var errorDescription: String? {
            switch self {
            case .unauthorized: "Administrator authorization invalid or expired."
            case .sourceMissing: "/Applications/nmap.app not found. Install nmap with the package from nmap.org."
            case .escapingSymlink(let p): "Symbolic link not allowed in nmap.app: \(p)"
            }
        }
    }

    /// Checks that the client obtained the admin right (password) on this AuthorizationRef.
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
                // No interaction: passes only if the client already entered the password.
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
        // The copy is now owned by root (no longer user-modifiable): compare it
        // with the installer receipt before making it active.
        try InstallerReceipt.verify(root: staging.path)

        // Atomic replacement of the previous copy.
        let old = parent.appending(path: ".nmap-old-\(UUID().uuidString)")
        if fm.fileExists(atPath: root.path) { try fm.moveItem(at: root, to: old) }
        try fm.moveItem(at: staging, to: root)
        try? fm.removeItem(at: old)

        return try TrustedNmap.check(root.appending(path: "bin/nmap").path)
    }

    /// root:wheel and no group/other write on every item; symbolic links
    /// must point inside the copy.
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
        let mode = (st.st_mode & 0o7777) & ~mode_t(0o7022) // no setuid/setgid/sticky, no g+w/o+w
        guard chmod(path, isDirectory ? (mode | 0o755) : mode) == 0 else { throw POSIXError(.EPERM) }
    }
}
