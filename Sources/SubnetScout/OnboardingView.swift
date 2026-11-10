import SwiftUI
import AppKit
import ScanKit

/// Configurazione guidata al primo avvio (riapribile da Aiuto › Configurazione guidata…).
struct OnboardingView: View {
    @Environment(AppModel.self) private var model
    let onDone: () -> Void

    @State private var step = 0
    @AppStorage(CVESettings.enabledKey) private var cveEnabled = false
    @AppStorage(ScheduleSettings.enabledKey) private var scheduleEnabled = false
    @AppStorage(ScheduleSettings.notifyKey) private var notify = true
    @AppStorage(ScheduleSettings.menuBarKey) private var showMenuBar = true

    private let titles = ["Benvenuto", "nmap", "Helper", "Opzioni", "Pronto"]

    var body: some View {
        VStack(spacing: 0) {
            HStack(spacing: 6) {
                ForEach(titles.indices, id: \.self) { i in
                    Capsule()
                        .fill(i <= step ? Color.accentColor : Color.secondary.opacity(0.25))
                        .frame(height: 4)
                }
            }
            .padding(.horizontal, 28)
            .padding(.top, 22)

            Group {
                switch step {
                case 0: welcome
                case 1: nmapStep
                case 2: helperStep
                case 3: optionsStep
                default: doneStep
                }
            }
            .frame(maxWidth: .infinity, maxHeight: .infinity, alignment: .topLeading)
            .padding(28)

            Divider()
            HStack {
                if step > 0 { Button("Indietro") { step -= 1 } }
                Spacer()
                if step == 0 {
                    Button("Accetto e continuo") { step += 1 }.keyboardShortcut(.defaultAction)
                } else if step < titles.count - 1 {
                    Button("Avanti") { step += 1 }.keyboardShortcut(.defaultAction)
                } else {
                    Button("Chiudi") { onDone() }
                    Button("Avvia la prima scansione") {
                        onDone()
                        model.startScan()
                    }
                    .keyboardShortcut(.defaultAction)
                    .disabled(model.nmapPath == nil)
                }
            }
            .padding(16)
        }
        .frame(width: 620, height: 560)
        .interactiveDismissDisabled()
    }

    // MARK: Passi

    private var welcome: some View {
        VStack(alignment: .leading, spacing: 14) {
            Label("Benvenuto in SubnetScout", systemImage: "dot.radiowaves.left.and.right")
                .font(.title.bold())
            Text("SubnetScout trova i dispositivi della tua rete, controlla i servizi che espongono e segnala configurazioni a rischio e vulnerabilità note.")
            GroupBox {
                VStack(alignment: .leading, spacing: 8) {
                    Label("Usalo in modo responsabile", systemImage: "hand.raised.fill").font(.headline)
                    Text("Scansiona solo reti di tua proprietà o per cui hai un'autorizzazione esplicita. In molti Paesi la scansione non autorizzata di sistemi altrui è illegale e può violare i termini del provider o dell'azienda.")
                    Text("I profili inclusi usano solo script NSE delle categorie «safe» e «default»: non tentano exploit né accessi con password.")
                        .foregroundStyle(.secondary)
                }
                .frame(maxWidth: .infinity, alignment: .leading)
                .padding(6)
            }
        }
    }

    private var nmapStep: some View {
        VStack(alignment: .leading, spacing: 14) {
            Text("1. nmap").font(.title2.bold())
            Text("SubnetScout usa nmap per le scansioni. nmap non è incluso nell'app per via della sua licenza.")
            if let path = model.nmapPath {
                status(ok: true, "nmap \(model.nmapVersion ?? "") trovato in \(path)")
            } else {
                status(ok: false, "nmap non è installato")
                Text("Installalo con Homebrew:").padding(.top, 4)
                HStack {
                    Text("brew install nmap")
                        .font(.body.monospaced())
                        .textSelection(.enabled)
                        .padding(6)
                        .background(.quaternary, in: RoundedRectangle(cornerRadius: 6))
                    Button("Copia") {
                        NSPasteboard.general.clearContents()
                        NSPasteboard.general.setString("brew install nmap", forType: .string)
                    }
                }
                Link("Oppure scarica il pacchetto ufficiale da nmap.org", destination: URL(string: "https://nmap.org/download.html#macosx")!)
                Button("Ricontrolla") { model.refreshEnvironment() }
            }
        }
    }

    private var helperStep: some View {
        VStack(alignment: .leading, spacing: 14) {
            Text("2. Helper (consigliato)").font(.title2.bold())
            Text("L'helper è un piccolo componente di sistema che esegue nmap con i privilegi necessari. Con l'helper:")
            VStack(alignment: .leading, spacing: 4) {
                Label("le scansioni non chiedono mai la password", systemImage: "key")
                Label("macOS non limita l'accesso alla rete locale, quindi i risultati sono completi", systemImage: "network")
                Label("funzionano le scansioni programmate", systemImage: "clock")
            }
            .font(.callout)
            Text("Esegue solo nmap con i profili dell'app e solo su reti private.")
                .font(.caption).foregroundStyle(.secondary)
            GroupBox { HelperStatusView().frame(maxWidth: .infinity, alignment: .leading).padding(4) }
            Text("Dopo l'installazione macOS chiede di approvarlo in Impostazioni di Sistema › Generali › Elementi login ed estensioni.")
                .font(.caption).foregroundStyle(.secondary)
        }
        .task { await model.refreshHelper() }
    }

    private var optionsStep: some View {
        VStack(alignment: .leading, spacing: 14) {
            Text("3. Opzioni").font(.title2.bold())
            Toggle(isOn: $cveEnabled) {
                VStack(alignment: .leading, spacing: 2) {
                    Text("Cerca vulnerabilità note (CVE)")
                    Text("Invia a NVD (NIST) solo nome e versione dei software trovati, mai dati dei dispositivi.")
                        .font(.caption).foregroundStyle(.secondary)
                }
            }
            Toggle(isOn: $scheduleEnabled) {
                VStack(alignment: .leading, spacing: 2) {
                    Text("Scansiona la rete ogni giorno")
                    Text("Frequenza, profilo e rete si cambiano in Impostazioni › Pianificazione.")
                        .font(.caption).foregroundStyle(.secondary)
                }
            }
            .onChange(of: scheduleEnabled) { model.scheduler.settingsChanged() }
            Toggle("Avvisami con una notifica quando cambia qualcosa", isOn: $notify)
                .disabled(!scheduleEnabled)
            Toggle("Mostra l'icona nella barra dei menu", isOn: $showMenuBar)
        }
    }

    private var doneStep: some View {
        VStack(alignment: .leading, spacing: 14) {
            Text("Pronto").font(.title2.bold())
            status(ok: model.nmapPath != nil, model.nmapPath != nil ? "nmap installato" : "nmap mancante: torna al passo 1")
            status(ok: model.usesHelper, model.usesHelper ? "Helper attivo" : "Helper non attivo: senza helper le scansioni possono chiedere la password ed essere limitate da macOS")
            status(ok: true, cveEnabled ? "Ricerca CVE attiva" : "Ricerca CVE disattivata")
            status(ok: true, scheduleEnabled ? "Scansione giornaliera attiva" : "Scansioni programmate disattivate")
            Text("Puoi riaprire questa configurazione da Aiuto › Configurazione guidata.")
                .font(.caption).foregroundStyle(.secondary)
        }
    }

    private func status(ok: Bool, _ text: String) -> some View {
        Label {
            Text(text).fixedSize(horizontal: false, vertical: true)
        } icon: {
            Image(systemName: ok ? "checkmark.circle.fill" : "exclamationmark.triangle.fill")
                .foregroundStyle(ok ? .green : .orange)
        }
    }
}
