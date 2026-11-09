import SwiftUI
import ScanKit

/// Vista «Rete»: gateway, DHCP, DNS, router UPnP e problemi a livello di rete.
struct NetworkPanel: View {
    @Environment(AppModel.self) private var model
    let result: ScanResult

    private static let networkRules: Set<String> = [
        "gateway-mac-changed", "gateway-mac-shared", "dhcp-rogue", "dhcp-router-mismatch",
        "dns-lan-host", "dns-unknown", "upnp-igd", "upnp-port-mapping", "router-management",
    ]

    var body: some View {
        if let net = result.network {
            Form {
                Section("Problemi di rete") {
                    let issues = result.findings.filter { Self.networkRules.contains($0.ruleID) }
                    if issues.isEmpty {
                        Label("Nessun problema a livello di rete", systemImage: "checkmark.shield")
                            .foregroundStyle(.secondary)
                    }
                    ForEach(issues) { f in
                        FindingRow(finding: f, hostName: result.hosts.first { $0.ip == f.hostIP }?.displayName)
                            .contentShape(Rectangle())
                            .onTapGesture { model.selectedHostID = f.hostIP }
                    }
                }

                Section("Gateway e DHCP") {
                    LabeledContent("Gateway") {
                        VStack(alignment: .trailing, spacing: 2) {
                            Text(join(net.gatewayIP, net.gatewayMAC))
                            if net.gatewayIP != nil, net.gatewayMAC == nil {
                                Text("MAC non disponibile: controllo ARP spoofing saltato. Verifica il permesso «Rete locale» di SubnetScout.")
                                    .font(.caption)
                                    .foregroundStyle(.orange)
                                    .multilineTextAlignment(.trailing)
                            }
                        }
                    }
                    LabeledContent("Interfaccia", value: join(net.interface, net.localIP))
                    LabeledContent("Server DHCP", value: net.dhcpServer ?? "—")
                    LabeledContent("DNS assegnati", value: net.dnsServers.isEmpty ? "—" : net.dnsServers.joined(separator: ", "))
                    LabeledContent("DHCP non autorizzati") {
                        if net.dhcpProbed {
                            Text(net.dhcpOffers.isEmpty
                                 ? "Nessuna offerta ricevuta"
                                 : net.dhcpOffers.map { "\($0.server)\($0.offeredIP.map { " → \($0)" } ?? "")" }.joined(separator: "\n"))
                        } else {
                            Text("Non controllato: serve «Come amministratore» con profilo Standard o Completo")
                                .foregroundStyle(.secondary)
                        }
                    }
                }

                Section("Router UPnP (porte aperte verso Internet)") {
                    if let error = net.upnpError {
                        Label(error, systemImage: "exclamationmark.triangle").foregroundStyle(.orange)
                    } else if !net.upnpProbed {
                        Text("Non controllato in questa scansione.").foregroundStyle(.secondary)
                    } else if net.upnpGateways.isEmpty {
                        Label("Nessun router con UPnP attivo", systemImage: "checkmark.shield")
                            .foregroundStyle(.secondary)
                    }
                    ForEach(net.upnpGateways) { gw in
                        VStack(alignment: .leading, spacing: 6) {
                            Text("\(gw.displayName) · \(gw.ip)").bold()
                            if gw.mappings.isEmpty {
                                Text(gw.mappingsReadable ? "UPnP attivo, nessuna porta inoltrata."
                                                         : "UPnP attivo, tabella delle porte non leggibile.")
                                    .font(.callout)
                                    .foregroundStyle(.secondary)
                            }
                            ForEach(Array(gw.mappings.enumerated()), id: \.offset) { _, m in
                                HStack {
                                    Text("\(m.externalPort)/\(m.proto.lowercased())")
                                        .font(.body.monospaced())
                                        .frame(width: 90, alignment: .leading)
                                    Image(systemName: "arrow.right")
                                    Text("\(m.internalClient):\(m.internalPort)").font(.body.monospaced())
                                    Text(m.description).foregroundStyle(.secondary).lineLimit(1)
                                    Spacer()
                                    if !m.enabled { Text("disattiva").font(.caption).foregroundStyle(.secondary) }
                                }
                            }
                        }
                        .padding(.vertical, 2)
                    }
                }
            }
            .formStyle(.grouped)
        } else {
            ContentUnavailableView("Nessun dato di rete",
                                   systemImage: "network.slash",
                                   description: Text("Questa scansione è stata fatta con una versione precedente di SubnetScout."))
        }
    }

    private func join(_ a: String?, _ b: String?) -> String {
        let parts = [a, b].compactMap { $0 }
        return parts.isEmpty ? "—" : parts.joined(separator: " · ")
    }
}
