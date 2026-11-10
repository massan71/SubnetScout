import SwiftUI
import ScanKit

struct ContentView: View {
    @Environment(AppModel.self) private var model
    /// Chi aveva già accettato l'avviso nelle versioni precedenti non rivede la configurazione.
    @AppStorage("onboardingDone") private var onboardingDone = UserDefaults.standard.bool(forKey: "acceptedDisclaimer")

    var body: some View {
        NavigationSplitView {
            SidebarView()
                .navigationSplitViewColumnWidth(min: 270, ideal: 300, max: 380)
        } content: {
            Group {
                if model.nmapPath == nil {
                    MissingNmapView()
                } else if let result = model.current {
                    ResultsView(result: result)
                } else {
                    ContentUnavailableView("Nessuna scansione",
                                           systemImage: "dot.radiowaves.left.and.right",
                                           description: Text("Scegli la subnet e premi «Avvia scansione» (⌘R)."))
                }
            }
            .navigationSplitViewColumnWidth(min: 560, ideal: 760)
        } detail: {
            if let host = model.selectedHost, let result = model.current {
                HostDetailView(host: host, result: result)
            } else {
                ContentUnavailableView("Seleziona un dispositivo", systemImage: "network")
            }
        }
        .toolbar { toolbar }
        .sheet(isPresented: Binding(get: { !onboardingDone || model.showOnboarding },
                                    set: { if !$0 { model.showOnboarding = false } })) {
            OnboardingView {
                onboardingDone = true
                model.showOnboarding = false
            }
            .environment(model)
        }
        .alert("Errore", isPresented: errorBinding) {
            Button("OK") { model.dismissError() }
        } message: {
            if case .failed(let msg) = model.phase { Text(msg) }
        }
    }

    private var errorBinding: Binding<Bool> {
        Binding(get: { if case .failed = model.phase { true } else { false } },
                set: { if !$0 { model.dismissError() } })
    }

    @ToolbarContentBuilder
    private var toolbar: some ToolbarContent {
        ToolbarItemGroup(placement: .primaryAction) {
            if model.isScanning {
                Button { model.cancelScan() } label: { Label("Interrompi", systemImage: "stop.fill") }
            } else {
                Button { model.startScan() } label: { Label("Avvia scansione", systemImage: "play.fill") }
                    .disabled(model.nmapPath == nil)
            }
            Menu {
                Button("Report HTML…") { model.export(.html) }
                Button("CSV (host e porte)…") { model.export(.csv) }
                Button("JSON (dati completi)…") { model.export(.json) }
            } label: {
                Label("Esporta", systemImage: "square.and.arrow.up")
            } primaryAction: {
                model.previewReport()
            }
            .disabled(model.current == nil)
            .help("Clic: apri il report nel browser. Freccia: esporta su file.")
        }
    }
}

struct MissingNmapView: View {
    @Environment(AppModel.self) private var model

    var body: some View {
        ContentUnavailableView {
            Label("nmap non è installato", systemImage: "exclamationmark.triangle")
        } description: {
            VStack(spacing: 8) {
                Text("SubnetScout usa nmap per le scansioni. Installalo con Homebrew:")
                Text("brew install nmap")
                    .font(.system(.body, design: .monospaced))
                    .textSelection(.enabled)
                    .padding(6)
                    .background(.quaternary, in: RoundedRectangle(cornerRadius: 6))
            }
        } actions: {
            Button("Riprova") { model.refreshEnvironment() }
        }
    }
}
