import Foundation
import Security
import CryptoKit

/// Signing requirements for the XPC connections between app and helper, derived from
/// the signature of the current process:
/// - Developer ID → same Apple chain and same Team ID;
/// - own certificate (e.g. "SubnetScout Code Signing") → same root certificate;
/// - ad-hoc signature → identifier only (weak: fine for development only).
public enum CodeSigning {
    public enum Kind: Equatable, Sendable {
        case team(String)
        case certificate(sha1: String)
        case adHoc
    }

    /// How the current process is signed.
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

    /// Requirement the process at the other end of the connection must satisfy.
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
