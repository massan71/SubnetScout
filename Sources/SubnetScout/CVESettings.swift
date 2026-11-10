import Foundation
import Security
import SwiftUI
import ScanKit

/// Impostazioni della ricerca CVE. La chiave API NVD sta nel Portachiavi.
enum CVESettings {
    static let enabledKey = "cveLookupEnabled"
    private static let keychainService = "net.sangalli.SubnetScout.nvd-api-key"

    static var enabled: Bool { UserDefaults.standard.bool(forKey: enabledKey) }

    static func apiKey() -> String? {
        let query: [String: Any] = [kSecClass as String: kSecClassGenericPassword,
                                    kSecAttrService as String: keychainService,
                                    kSecReturnData as String: true,
                                    kSecMatchLimit as String: kSecMatchLimitOne]
        var item: CFTypeRef?
        guard SecItemCopyMatching(query as CFDictionary, &item) == errSecSuccess, let data = item as? Data else { return nil }
        return String(data: data, encoding: .utf8)
    }

    @discardableResult
    static func setAPIKey(_ key: String?) -> Bool {
        let base: [String: Any] = [kSecClass as String: kSecClassGenericPassword,
                                   kSecAttrService as String: keychainService]
        SecItemDelete(base as CFDictionary)
        guard let key = key?.trimmingCharacters(in: .whitespacesAndNewlines), !key.isEmpty else { return true }
        var add = base
        add[kSecValueData as String] = Data(key.utf8)
        add[kSecAttrAccessible as String] = kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly
        return SecItemAdd(add as CFDictionary, nil) == errSecSuccess
    }
}

/// Scheda «Vulnerabilità» delle Impostazioni.
struct CVESettingsView: View {
    @AppStorage(CVESettings.enabledKey) private var cveEnabled = false
    @State private var apiKey = ""
    @State private var saved = false

    var body: some View {
        Form {
            Section {
                Toggle("Look up known vulnerabilities (CVE)", isOn: $cveEnabled)
                Text("After each scan with ports, SubnetScout asks NIST's NVD database for the CVEs of the software found. **Only the software name and version** are sent (e.g. “openssh 9.6”), never addresses, names or other data about your devices. Responses are cached on this Mac for 7 days.")
                    .font(.callout)
                    .foregroundStyle(.secondary)
                Text("Matching is based on the reported version: routers, NAS devices and cameras often fix flaws without changing their version, so some results may be false positives.")
                    .font(.caption)
                    .foregroundStyle(.secondary)
            } header: { Text("Known vulnerabilities") }

            Section {
                SecureField("NVD API key (optional)", text: $apiKey)
                HStack {
                    Button("Save Key") {
                        saved = CVESettings.setAPIKey(apiKey)
                    }
                    Button("Remove") {
                        apiKey = ""
                        CVESettings.setAPIKey(nil)
                        saved = false
                    }
                    if saved { Label("Saved in the Keychain", systemImage: "checkmark").foregroundStyle(.green).font(.caption) }
                }
                Text("Without a key, NVD accepts 5 requests every 30 seconds, so the first lookup can take a few minutes. With a free key (nvd.nist.gov/developers/request-an-api-key) it is about 10 times faster.")
                    .font(.caption)
                    .foregroundStyle(.secondary)
                Button("Clear CVE Cache") { NVDClient.clearCache() }
            } header: { Text("NVD") }
        }
        .formStyle(.grouped)
        .onAppear { apiKey = CVESettings.apiKey() ?? "" }
    }
}
