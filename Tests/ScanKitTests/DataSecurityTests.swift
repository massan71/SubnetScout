import Foundation
import Testing
import CryptoKit
@testable import ScanKit

@Suite struct EncryptedHistoryTests {
    func tempDir() -> URL {
        FileManager.default.temporaryDirectory.appending(path: "hist-\(UUID().uuidString)")
    }

    func sample() -> ScanResult {
        ScanResult(target: "192.168.1.0/24", profile: .quick, privileged: false, startedAt: Date(timeIntervalSince1970: 1),
                   finishedAt: Date(timeIntervalSince1970: 2), hosts: [Host(ip: "192.168.1.77", hostnames: ["segreto.lan"])],
                   findings: [])
    }

    @Test func roundTripIsEncryptedAndPrivate() throws {
        let dir = tempDir(); defer { try? FileManager.default.removeItem(at: dir) }
        let key = SymmetricKey(size: .bits256)
        let store = ScanHistoryStore(directory: dir, keyProvider: { key })
        let r = sample()
        try store.save(r)

        let files = try FileManager.default.contentsOfDirectory(at: dir, includingPropertiesForKeys: nil)
        #expect(files.map(\.pathExtension) == ["ssenc"])
        let raw = try Data(contentsOf: files[0])
        #expect(raw.range(of: Data("segreto.lan".utf8)) == nil, "nessun dato in chiaro su disco")
        #expect(raw.range(of: Data("192.168.1.77".utf8)) == nil)

        let perms = try FileManager.default.attributesOfItem(atPath: files[0].path)[.posixPermissions] as? Int
        #expect(perms == 0o600)
        let dirPerms = try FileManager.default.attributesOfItem(atPath: dir.path)[.posixPermissions] as? Int
        #expect(dirPerms == 0o700)

        #expect(store.loadAll().map(\.id) == [r.id])
        #expect(store.loadAll().first?.hosts.first?.hostnames == ["segreto.lan"])
    }

    @Test func migratesPlaintextScans() throws {
        let dir = tempDir(); defer { try? FileManager.default.removeItem(at: dir) }
        try FileManager.default.createDirectory(at: dir, withIntermediateDirectories: true)
        let r = sample()
        try ScanHistoryStore.encoder().encode(r).write(to: dir.appending(path: "\(r.id.uuidString).json"))
        let key = SymmetricKey(size: .bits256)
        let store = ScanHistoryStore(directory: dir, keyProvider: { key })

        #expect(store.loadAll().map(\.id) == [r.id])
        let names = try FileManager.default.contentsOfDirectory(atPath: dir.path)
        #expect(names == ["\(r.id.uuidString).ssenc"], "il file in chiaro va eliminato dopo la cifratura")
    }

    @Test func wrongKeyIsReportedNotCrashing() throws {
        let dir = tempDir(); defer { try? FileManager.default.removeItem(at: dir) }
        try ScanHistoryStore(directory: dir, keyProvider: { SymmetricKey(size: .bits256) }).save(sample())
        let other = ScanHistoryStore(directory: dir, keyProvider: { SymmetricKey(size: .bits256) })
        #expect(other.loadAll().isEmpty)
        #expect(other.unreadableCount() == 1)
    }

    @Test func deleteRemovesEncryptedFile() throws {
        let dir = tempDir(); defer { try? FileManager.default.removeItem(at: dir) }
        let key = SymmetricKey(size: .bits256)
        let store = ScanHistoryStore(directory: dir, keyProvider: { key })
        let r = sample()
        try store.save(r)
        store.delete(r.id)
        #expect(store.loadAll().isEmpty)
    }
}

@Suite struct ReceiptTests {
    @Test func parsesBOMAndCksum() {
        let bom = """
        ./nmap.app/Contents/Resources/bin/nmap\t-rwxr-xr-x \t4600496\t1380532347
        ./nmap.app/Contents/Resources/lib\tdrwxr-xr-x \t\t
        ./nmap.app/Contents/Resources/lib/libz.dylib\tlrwxr-xr-x \t16\t123
        ./zenmap.app/x\t-rw-r--r-- \t1\t2
        """
        let e = InstallerReceipt.parseBOM(bom, prefix: InstallerReceipt.bomPrefix)
        #expect(e == ["bin/nmap": .init(size: 4600496, cksum: 1380532347)])
        let ck = InstallerReceipt.parseCksum("1380532347 4600496 /r/bin/nmap\n", root: "/r")
        #expect(ck == e)
    }

    @Test func compareDetectsChanges() {
        let good: [String: InstallerReceipt.Entry] = ["bin/nmap": .init(size: 10, cksum: 1), "share/a": .init(size: 2, cksum: 2)]
        #expect(throws: Never.self) { try InstallerReceipt.compare(expected: good, actual: good) }
        #expect(throws: InstallerReceipt.Mismatch.modified("bin/nmap")) {
            try InstallerReceipt.compare(expected: good, actual: ["bin/nmap": .init(size: 10, cksum: 9), "share/a": good["share/a"]!])
        }
        #expect(throws: InstallerReceipt.Mismatch.unexpected("lib/evil.dylib")) {
            try InstallerReceipt.compare(expected: good, actual: good.merging(["lib/evil.dylib": .init(size: 1, cksum: 1)]) { a, _ in a })
        }
        #expect(throws: InstallerReceipt.Mismatch.missing("share/a")) {
            try InstallerReceipt.compare(expected: good, actual: ["bin/nmap": good["bin/nmap"]!])
        }
    }

    /// Il vero nmap.app installato (e la copia protetta) devono corrispondere alla ricevuta.
    @Test(.enabled(if: FileManager.default.fileExists(atPath: InstallerReceipt.receiptBOM)
                   && FileManager.default.fileExists(atPath: TrustedNmap.adoptionSource)))
    func installedNmapMatchesReceipt() throws {
        try InstallerReceipt.verify(root: TrustedNmap.adoptionSource)
        if FileManager.default.fileExists(atPath: TrustedNmap.adoptedRoot) {
            try InstallerReceipt.verify(root: TrustedNmap.adoptedRoot)
        }
    }
}

@Suite struct ReportSecurityTests {
    @Test func reportHasStrictCSP() {
        let r = ScanResult(target: "x", profile: .quick, privileged: false, startedAt: .now, finishedAt: .now, hosts: [], findings: [])
        let html = ReportGenerator.html(for: r)
        #expect(html.contains("http-equiv=\"Content-Security-Policy\""))
        #expect(html.contains("default-src 'none'"))
        #expect(!html.contains("<script"))
        #expect(html.contains("name=\"referrer\" content=\"no-referrer\""))
    }
}
