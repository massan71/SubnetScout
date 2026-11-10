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
                if net.localNetworkBlocked == true {
                    Section {
                        Label(ScanEngine.localNetworkMessage + " Until then, ARP spoofing and UPnP checks are not reliable.",
                              systemImage: "lock.trianglebadge.exclamationmark")
                            .foregroundStyle(.orange)
                    }
                }
                Section("Network issues") {
                    let issues = result.findings.filter { Self.networkRules.contains($0.ruleID) }
                    if issues.isEmpty {
                        Label("No network-level issues", systemImage: "checkmark.shield")
                            .foregroundStyle(.secondary)
                    }
                    ForEach(issues) { f in
                        FindingRow(finding: f, hostName: result.hosts.first { $0.ip == f.hostIP }?.displayName)
                            .contentShape(Rectangle())
                            .onTapGesture { model.selectedHostID = f.hostIP }
                    }
                }

                Section("Gateway and DHCP") {
                    LabeledContent("Gateway") {
                        VStack(alignment: .trailing, spacing: 2) {
                            Text(join(net.gatewayIP, net.gatewayMAC))
                            if net.gatewayIP != nil, net.gatewayMAC == nil {
                                Text("MAC not available: ARP spoofing check skipped. Check SubnetScout's “Local Network” permission.")
                                    .font(.caption)
                                    .foregroundStyle(.orange)
                                    .multilineTextAlignment(.trailing)
                            }
                        }
                    }
                    LabeledContent("Interface", value: join(net.interface, net.localIP))
                    LabeledContent("DHCP server", value: net.dhcpServer ?? "—")
                    LabeledContent("Assigned DNS", value: net.dnsServers.isEmpty ? "—" : net.dnsServers.joined(separator: ", "))
                    LabeledContent("Rogue DHCP servers") {
                        if net.dhcpProbed {
                            Text(net.dhcpOffers.isEmpty
                                 ? "No answer to the probe, not even from the expected server: some routers do not respond, so the check is inconclusive"
                                 : net.dhcpOffers.map { "\($0.server)\($0.offeredIP.map { " → \($0)" } ?? "")" }.joined(separator: "\n"))
                        } else {
                            Text("Not checked: requires “As administrator” with the Standard or Full profile")
                                .foregroundStyle(.secondary)
                        }
                    }
                }

                Section("UPnP routers (ports open to the Internet)") {
                    if let error = net.upnpError {
                        Label(error, systemImage: "exclamationmark.triangle").foregroundStyle(.orange)
                    } else if !net.upnpProbed {
                        Text("Not checked in this scan.").foregroundStyle(.secondary)
                    } else if net.upnpGateways.isEmpty {
                        Label("No router with UPnP enabled", systemImage: "checkmark.shield")
                            .foregroundStyle(.secondary)
                    }
                    ForEach(net.upnpGateways) { gw in
                        VStack(alignment: .leading, spacing: 6) {
                            Text("\(gw.displayName) · \(gw.ip)").bold()
                            if gw.mappings.isEmpty {
                                Text(gw.mappingsReadable ? "UPnP enabled, no forwarded ports."
                                                         : "UPnP enabled, port mapping table not readable.")
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
                                    if !m.enabled { Text("disabled").font(.caption).foregroundStyle(.secondary) }
                                }
                            }
                        }
                        .padding(.vertical, 2)
                    }
                }
            }
            .formStyle(.grouped)
        } else {
            ContentUnavailableView("No network data",
                                   systemImage: "network.slash",
                                   description: Text("This scan was made with an earlier version of SubnetScout."))
        }
    }

    private func join(_ a: String?, _ b: String?) -> String {
        let parts = [a, b].compactMap { $0 }
        return parts.isEmpty ? "—" : parts.joined(separator: " · ")
    }
}
