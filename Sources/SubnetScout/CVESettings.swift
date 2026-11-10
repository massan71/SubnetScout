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

/// Finestra Impostazioni (⌘,).
struct SettingsView: View {
    @AppStorage(CVESettings.enabledKey) private var cveEnabled = false
    @State private var apiKey = ""
    @State private var saved = false

    var body: some View {
        Form {
            Section {
                Toggle("Cerca vulnerabilità note (CVE)", isOn: $cveEnabled)
                Text("Dopo ogni scansione con le porte, SubnetScout chiede al database NVD del NIST le CVE dei software trovati. Viene inviato **solo il nome e la versione del software** (es. «openssh 9.6»), mai indirizzi, nomi o altri dati dei tuoi dispositivi. Le risposte restano in cache sul Mac per 7 giorni.")
                    .font(.callout)
                    .foregroundStyle(.secondary)
                Text("La corrispondenza è basata sulla versione dichiarata: router, NAS e telecamere spesso correggono le falle senza cambiare versione, quindi alcuni risultati possono essere falsi positivi.")
                    .font(.caption)
                    .foregroundStyle(.secondary)
            } header: { Text("Vulnerabilità note") }

            Section {
                SecureField("Chiave API NVD (facoltativa)", text: $apiKey)
                HStack {
                    Button("Salva chiave") {
                        saved = CVESettings.setAPIKey(apiKey)
                    }
                    Button("Rimuovi") {
                        apiKey = ""
                        CVESettings.setAPIKey(nil)
                        saved = false
                    }
                    if saved { Label("Salvata nel Portachiavi", systemImage: "checkmark").foregroundStyle(.green).font(.caption) }
                }
                Text("Senza chiave NVD accetta 5 richieste ogni 30 secondi, quindi la prima ricerca può richiedere qualche minuto. Con una chiave gratuita (nvd.nist.gov/developers/request-an-api-key) è circa 10 volte più veloce.")
                    .font(.caption)
                    .foregroundStyle(.secondary)
                Button("Svuota la cache CVE") { NVDClient.clearCache() }
            } header: { Text("NVD") }
        }
        .formStyle(.grouped)
        .frame(width: 520)
        .onAppear { apiKey = CVESettings.apiKey() ?? "" }
    }
}
