import Foundation
import Security
import CryptoKit

/// Requisiti di firma per le connessioni XPC tra app e helper, ricavati dalla
/// firma del processo corrente:
/// - Developer ID → stessa catena Apple e stesso Team ID;
/// - certificato proprio (es. «SubnetScout Code Signing») → stesso certificato radice;
/// - firma ad-hoc → solo l'identificatore (debole: va bene solo in sviluppo).
public enum CodeSigning {
    public enum Kind: Equatable, Sendable {
        case team(String)
        case certificate(sha1: String)
        case adHoc
    }

    /// Come è firmato il processo corrente.
    public static func current() -> Kind {
        var code: SecCode?
        var staticCode: SecStaticCode?
        var info: CFDictionary?
        guard SecCodeCopySelf([], &code) == errSecSuccess, let code,
              SecCodeCopyStaticCode(code, [], &staticCode) == errSecSuccess, let staticCode,
              SecCodeCopySigningInformation(staticCode, SecCSFlags(rawValue: kSecCSSigningInformation), &info) == errSecSuccess,
              let dict = info as? [String: Any]
        else { return .adHoc }
        if let team = dict[kSecCodeInfoTeamIdentifier as String] as? String, !team.isEmpty {
            return .team(team)
        }
        if let certs = dict[kSecCodeInfoCertificates as String] as? [SecCertificate], let root = certs.last {
            let data = SecCertificateCopyData(root) as Data
            return .certificate(sha1: Insecure.SHA1.hash(data: data).map { String(format: "%02x", $0) }.joined())
        }
        return .adHoc
    }

    /// Requisito che il processo all'altro capo della connessione deve soddisfare.
    public static func requirement(forPeer identifier: String, signedLike kind: Kind = current()) -> String {
        let base = "identifier \"\(identifier)\""
        switch kind {
        case .team(let team):
            return "anchor apple generic and \(base) and certificate leaf[subject.OU] = \"\(team)\""
        case .certificate(let sha1):
            return "\(base) and certificate root = H\"\(sha1)\""
        case .adHoc:
            return base
        }
    }
}
