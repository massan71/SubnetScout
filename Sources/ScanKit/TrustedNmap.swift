import Foundation
import Darwin

/// Checks that an nmap installation can safely be run as root.
///
/// A root daemon that runs user-writable files amounts to giving passwordless root
/// to any of the user's processes. That is why the binary, the dynamic libraries
/// (including those via @rpath), the data directory (NSE scripts included) and every
/// folder containing them must be owned by root and not
/// writable by others.
///
/// - Homebrew's nmap does NOT pass (everything is owned by the user).
/// - /Applications/nmap.app (nmap.org installer ≥ 7.99) does NOT pass: /Applications
///   is writable by the admin group. The helper can however "adopt" it, copying it to
///   `adoptedRoot` (root-owned) after an administrator authorization.
/// - /usr/local (older nmap.org installers) and MacPorts (/opt/local) pass.
public enum TrustedNmap {
    public struct Resolved: Sendable, Equatable {
        public let binary: String
        public let dataDir: String
    }

    public enum Problem: LocalizedError, Equatable {
        case notFound
        case untrustedPath(String)
        case untrustedLibrary(String)
        case unreadableBinary(String)
        case dataDirMissing(String)

        public var errorDescription: String? {
            switch self {
            case .notFound:
                "No nmap that can safely run as root was found."
            case .untrustedPath(let p):
                "“\(p)” is not owned by root or is writable by other users: running it as root is not safe."
            case .untrustedLibrary(let l):
                "nmap loads an unprotected library (“\(l)”): running it as root is not safe."
            case .unreadableBinary(let p):
                "Cannot analyze the binary “\(p)”."
            case .dataDirMissing(let p):
                "nmap data directory not found in “\(p)”."
            }
        }
    }

    /// Protected copy created by the helper from nmap.app.
    public static let adoptedRoot = "/Library/Application Support/SubnetScout/nmap"
    /// Installation the protected copy can be created from.
    public static let adoptionSource = "/Applications/nmap.app/Contents/Resources"

    /// Order of preference: protected copy, old official package, MacPorts, Homebrew.
    public static let candidates = [
        adoptedRoot + "/bin/nmap",
        "/usr/local/bin/nmap",
        "/opt/local/bin/nmap",
        "/opt/homebrew/bin/nmap",
    ]

    /// true if nmap.app exists but there is no valid protected copy yet.
    public static var canAdopt: Bool {
        FileManager.default.isExecutableFile(atPath: adoptionSource + "/bin/nmap")
            && (try? check(adoptedRoot + "/bin/nmap")) == nil
    }

    /// The first trusted nmap, or the problem with the first one found.
    public static func resolve(candidates: [String] = candidates) -> Result<Resolved, Problem> {
        var firstProblem: Problem?
        for path in candidates where FileManager.default.fileExists(atPath: path) {
            do {
                return .success(try check(path))
            } catch let p as Problem {
                if firstProblem == nil { firstProblem = p }
            } catch {
                if firstProblem == nil { firstProblem = .unreadableBinary(path) }
            }
        }
        return .failure(firstProblem ?? .notFound)
    }

    public static func check(_ path: String) throws -> Resolved {
        let binary = try checkBinary(path)
        let dataDir = URL(fileURLWithPath: binary).deletingLastPathComponent().deletingLastPathComponent()
            .appending(path: "share/nmap").path
        guard FileManager.default.fileExists(atPath: dataDir + "/nmap-services") else {
            throw Problem.dataDirMissing(dataDir)
        }
        try checkTree(dataDir)
        return Resolved(binary: binary, dataDir: dataDir)
    }

    /// Checks the binary and libraries (recursively); returns the real path of the binary.
    @discardableResult
    public static func checkBinary(_ path: String) throws -> String {
        let real = try realPath(path)
        try checkAncestors(real)
        var visited = Set<String>()
        try checkImage(real, executableDir: dirname(real), inheritedRpaths: [], visited: &visited)
        return real
    }

    private static func checkImage(_ image: String, executableDir: String, inheritedRpaths: [String],
                                   visited: inout Set<String>) throws {
        guard visited.insert(image).inserted else { return }
        let info: MachOInfo
        do { info = try machO(of: image) } catch { throw Problem.unreadableBinary(image) }
        if info.setsDyldEnvironment { throw Problem.untrustedLibrary("LC_DYLD_ENVIRONMENT in \(image)") }

        let loaderDir = dirname(image)
        func expand(_ p: String) -> String? {
            if p.hasPrefix("@executable_path") { return executableDir + p.dropFirst("@executable_path".count) }
            if p.hasPrefix("@loader_path") { return loaderDir + p.dropFirst("@loader_path".count) }
            return p.hasPrefix("/") ? p : nil
        }
        // dyld looks up @rpath first in the image's rpaths, then in those of whoever loaded it.
        let rpaths = info.rpaths.compactMap(expand) + inheritedRpaths

        for lib in info.dylibs {
            if lib.hasPrefix("/usr/lib/") || lib.hasPrefix("/System/") { continue } // protected by SIP
            let candidates: [String]
            if lib.hasPrefix("@rpath/") {
                candidates = rpaths.map { $0 + "/" + lib.dropFirst("@rpath/".count) }
            } else if let p = expand(lib) {
                candidates = [p]
            } else {
                throw Problem.untrustedLibrary(lib)
            }
            // Every location dyld examines before the right one must be protected:
            // otherwise an attacker could plant a library there that would be loaded first.
            var found: String?
            for c in candidates {
                do { try checkPotentialPath(c) } catch { throw Problem.untrustedLibrary(lib) }
                if FileManager.default.fileExists(atPath: c) { found = c; break }
            }
            guard let found, let real = try? realPath(found) else { throw Problem.untrustedLibrary(lib) }
            do { try checkAncestors(real) } catch { throw Problem.untrustedLibrary(lib) }
            try checkImage(real, executableDir: executableDir, inheritedRpaths: rpaths, visited: &visited)
        }
    }

    // MARK: - Permissions

    static func dirname(_ p: String) -> String { (p as NSString).deletingLastPathComponent }

    static func realPath(_ path: String) throws -> String {
        guard let r = realpath(path, nil) else { throw Problem.untrustedPath(path) }
        defer { free(r) }
        return String(cString: r)
    }

    static func isSafe(_ st: stat) -> Bool {
        let mode = st.st_mode
        return st.st_uid == 0
            && mode & S_IWOTH == 0
            && (mode & S_IWGRP == 0 || st.st_gid == 0)
    }

    /// The file and every folder up to "/" must be owned by root and not writable by others.
    static func checkAncestors(_ realPath: String) throws {
        var url = URL(fileURLWithPath: realPath)
        while true {
            var st = stat()
            guard lstat(url.path, &st) == 0, isSafe(st) else { throw Problem.untrustedPath(url.path) }
            if url.path == "/" { break }
            url.deleteLastPathComponent()
        }
    }

    /// For a path that may not exist: the first existing ancestor must
    /// be protected (so nobody can create files inside it).
    static func checkPotentialPath(_ path: String) throws {
        var url = URL(fileURLWithPath: path)
        while !FileManager.default.fileExists(atPath: url.path) {
            url.deleteLastPathComponent()
        }
        try checkAncestors(try realPath(url.path))
    }

    /// Recursive check of the data directory (NSE scripts, nselib, …).
    static func checkTree(_ dir: String) throws {
        let real = try realPath(dir)
        try checkAncestors(real)
        guard let walker = FileManager.default.enumerator(atPath: real) else { throw Problem.untrustedPath(real) }
        for case let rel as String in walker {
            let p = real + "/" + rel
            var st = stat()
            guard lstat(p, &st) == 0 else { throw Problem.untrustedPath(p) }
            if st.st_mode & S_IFMT == S_IFLNK {
                try checkAncestors(try realPath(p))
            } else if !isSafe(st) {
                throw Problem.untrustedPath(p)
            }
        }
    }

    // MARK: - Mach-O

    struct MachOInfo {
        var dylibs: [String] = []
        var rpaths: [String] = []
        var setsDyldEnvironment = false
    }

    /// Dynamic libraries loaded by a Mach-O binary (thin or universal).
    public static func dylibs(of path: String) throws -> [String] {
        try machO(of: path).dylibs
    }

    static func machO(of path: String) throws -> MachOInfo {
        let data = try Data(contentsOf: URL(fileURLWithPath: path), options: .alwaysMapped)
        struct Bad: Error {}

        func u32(_ o: Int, bigEndian: Bool) throws -> UInt32 {
            guard o >= 0, o + 4 <= data.count else { throw Bad() }
            let v = data.withUnsafeBytes { $0.loadUnaligned(fromByteOffset: o, as: UInt32.self) }
            return bigEndian ? UInt32(bigEndian: v) : UInt32(littleEndian: v)
        }
        func u64be(_ o: Int) throws -> UInt64 {
            guard o >= 0, o + 8 <= data.count else { throw Bad() }
            return UInt64(bigEndian: data.withUnsafeBytes { $0.loadUnaligned(fromByteOffset: o, as: UInt64.self) })
        }
        func lcString(_ cmdStart: Int, _ cmdSize: Int) throws -> String {
            let start = cmdStart + Int(try u32(cmdStart + 8, bigEndian: false))
            guard start < cmdStart + cmdSize else { throw Bad() }
            return String(decoding: data[start..<(cmdStart + cmdSize)].prefix { $0 != 0 }, as: UTF8.self)
        }

        var slices: [Int] = []
        let fatMagic = try u32(0, bigEndian: true)
        if fatMagic == 0xCAFEBABE || fatMagic == 0xCAFEBABF {
            let is64 = fatMagic == 0xCAFEBABF
            let n = Int(try u32(4, bigEndian: true))
            guard n > 0, n < 32 else { throw Bad() }
            for i in 0..<n {
                let base = 8 + i * (is64 ? 32 : 20)
                slices.append(is64 ? Int(try u64be(base + 8)) : Int(try u32(base + 8, bigEndian: true)))
            }
        } else {
            slices = [0]
        }

        let loadDylibCmds: Set<UInt32> = [0xC, 0x80000018, 0x8000001F, 0x20, 0x80000023]
        let lcRpath: UInt32 = 0x8000001C
        let lcDyldEnvironment: UInt32 = 0x27
        var dylibs: [String] = []
        var rpaths: [String] = []
        var info = MachOInfo()
        for s in slices {
            let magic = try u32(s, bigEndian: false)
            guard magic == 0xFEEDFACF || magic == 0xFEEDFACE else { throw Bad() }
            let ncmds = Int(try u32(s + 16, bigEndian: false))
            var off = s + (magic == 0xFEEDFACF ? 32 : 28)
            for _ in 0..<ncmds {
                let cmd = try u32(off, bigEndian: false)
                let size = Int(try u32(off + 4, bigEndian: false))
                guard size >= 12 || !(loadDylibCmds.contains(cmd) || cmd == lcRpath), size >= 8,
                      off + size <= data.count else { throw Bad() }
                if loadDylibCmds.contains(cmd) {
                    let name = try lcString(off, size)
                    if !dylibs.contains(name) { dylibs.append(name) }
                } else if cmd == lcRpath {
                    let p = try lcString(off, size)
                    if !rpaths.contains(p) { rpaths.append(p) }
                } else if cmd == lcDyldEnvironment {
                    info.setsDyldEnvironment = true
                }
                off += size
            }
        }
        info.dylibs = dylibs
        info.rpaths = rpaths
        return info
    }
}
