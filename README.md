# SubnetScout

Scanner di rete nativo per macOS (SwiftUI) basato su **nmap**: discovery della subnet, audit di sicurezza e report.

> ⚠️ Usalo solo su reti tue o per cui hai un'autorizzazione esplicita.

## Requisiti

- macOS 14+
- nmap: `brew install nmap` (non è incluso nell'app per via della licenza NPSL)
- Xcode (o Command Line Tools con Swift 6) per compilare

## Installare

```bash
brew install --cask massan71/tap/subnetscout
```

Installa anche la formula `nmap`. In alternativa scarica lo zip dalle [release](https://github.com/massan71/SubnetScout/releases).
La build è firmata ad-hoc e non notarizzata: il cask rimuove la quarantena, mentre con lo zip serve «Apri comunque» in Privacy e sicurezza.

## Compilare e avviare

```bash
swift run SubnetScout          # sviluppo
scripts/bundle.sh --open       # crea build/SubnetScout.app (universale) e la avvia
swift test                     # test (incluso uno scan reale di 127.0.0.1)
```

Per lavorare in Xcode: `open Package.swift`.

Icona: `swift scripts/make-icon.swift` rigenera `Resources/AppIcon.icns` (disegnata in CoreGraphics).

Release: `scripts/release.sh 0.1.0 release-notes/0.1.0.md` (test, build universale, zip verificato, tag e release su GitHub).

Se `xcode-select` punta ai Command Line Tools, anteponi
`DEVELOPER_DIR=/Applications/Xcode.app/Contents/Developer`.

## Privileged helper

Con «Come amministratore» l'app usa un daemon root (`SubnetScoutHelper`, registrato
con `SMAppService`) invece di chiedere la password a ogni scansione.

1. Attiva «Come amministratore» e premi **Installa helper…**
2. Approva SubnetScout in *Impostazioni di Sistema › Generali › Elementi login ed estensioni*

Il helper espone via XPC solo «esegui il profilo X sui target Y». Le misure di sicurezza:
- **Argomenti decisi dal helper**: costruisce lui gli argomenti di nmap e rivalida profilo e target, quindi un client non può fargli eseguire comandi arbitrari come root.
- **Client verificato**: accetta solo connessioni firmate `net.sangalli.SubnetScout`. Con firma Developer ID richiede anche lo stesso Team ID (`SIGN_IDENTITY=… scripts/bundle.sh`).
- **Solo nmap di root**: esegue nmap solo se binario, librerie, script NSE e cartelle sono di root e non scrivibili da altri (`TrustedNmap`).
  - **nmap di Homebrew non passa**, perché appartiene al tuo utente: eseguirlo come root senza password darebbe root a qualsiasi programma. In quel caso l'app ricade sulla richiesta della password.
  - Per usare il helper installa anche il **pacchetto ufficiale di nmap.org**. Dalla 7.99 l'installer lo mette in `/Applications/nmap.app`, che il gruppo admin può modificare, quindi non è affidabile così com'è.
  - Premi **Copia nmap in posizione protetta…**: dopo la password amministratore il helper lo copia in `/Library/Application Support/SubnetScout/nmap` (root:wheel). Rifallo quando aggiorni nmap.
  - Va bene anche MacPorts, e i vecchi installer che usavano `/usr/local/bin/nmap`.
  - Le librerie `@rpath`/`@executable_path` vengono risolte e verificate una per una.
- **Ambiente isolato**: ambiente azzerato, cwd `/`, al massimo 2 scansioni insieme. Si chiude da solo dopo 30 s di inattività e launchd lo riavvia su richiesta.

Disinstallazione: dal pulsante nell'app, oppure eliminando l'app. La copia protetta di nmap
resta: per rimuoverla `sudo rm -rf "/Library/Application Support/SubnetScout"`.

### Firma, permessi di macOS e helper

- `bundle.sh` firma con il certificato **«SubnetScout Code Signing»** se è nel portachiavi, altrimenti ad-hoc.
  Con il certificato app e helper si verificano a vicenda (`certificate root = H"…"`).
- **Rete locale**: macOS può negare il permesso all'app anche se l'interruttore in Impostazioni è attivo, ad esempio
  dopo aver cambiato firma o con più copie dell'app con lo stesso bundle ID. Per questo, quando l'helper è attivo,
  è lui a leggere la tabella ARP e cercare i router UPnP: come daemon di sistema non è soggetto al permesso.
  Senza helper la vista Rete avvisa se la rete locale è bloccata.
- **Approvazione dell'helper**: senza un Developer ID, macOS lega l'approvazione all'hash del binario dell'helper.
  Quando l'helper cambia, premi **Reinstalla** e riapprova. Solo una firma Developer ID evita di farlo.
- **Una sola copia installata**: tieni l'app solo in `/Applications`. Due copie con lo stesso bundle ID confondono
  i permessi di macOS.
- Diagnostica: `/Applications/SubnetScout.app/Contents/MacOS/SubnetScout --diagnose-network`.
- Verifica visiva: `… --qa-snapshots <cartella>` salva uno screenshot delle viste principali (con i dati reali dello storico).
- **Portachiavi**: lo storico è cifrato con una chiave nel Portachiavi. Senza Developer ID, macOS lega l'accesso
  all'hash del binario: dopo ogni aggiornamento chiede di nuovo il permesso («Consenti sempre»). L'app nel frattempo
  resta utilizzabile.

## Funzioni

| Area | Cosa fa |
|---|---|
| **Discovery** | Nomi e modelli da Bonjour/mDNS (stampanti, speaker, TV, dispositivi smart). Rileva da solo interfaccia e subnet, ARP/ping sweep, MAC dalla tabella ARP anche senza root, produttore dal database OUI di nmap, riconosce i MAC randomizzati, il gateway e il tipo di dispositivo |
| **Profili** | Discovery · Veloce (top 100) · Standard + audit (top 1000 + script) · Completo (65535 TCP + UDP principali) |
| **Amministratore** | SYN scan, OS detection, UDP, MAC: password richiesta con la finestra standard di macOS |
| **Audit** | ~35 regole: Telnet, FTP anonimo, SMBv1, firma SMB, TLS obsoleto o debole, DH deboli, certificati scaduti o self-signed, HTTPS senza HSTS, metodi HTTP rischiosi, RDP senza NLA, VNC senza password, DB esposti, API Docker, SNMP `public`, chiavi SSH deboli… |
| **Rete** | MAC del gateway cambiato o condiviso da un altro IP (ARP spoofing), server DHCP non autorizzati (`broadcast-dhcp-discover`, come amministratore), DNS anomali, router UPnP e **porte aperte verso Internet** (lettura della tabella IGD), gestione del router accessibile |
| **CVE** | Facoltativo e disattivato di default: i CPE rilevati da nmap (`-sV`) vengono cercati nel database NVD del NIST. Viene inviato solo prodotto e versione, mai dati dei dispositivi. Le risposte restano in cache 7 giorni, con badge per le CVE sfruttate attivamente (CISA KEV) e chiave API NVD facoltativa nel Portachiavi |
| **Pianificazione** | Scansioni automatiche (ogni ora, ogni 6 ore, ogni giorno, ogni settimana) tramite l'helper, senza password. Notifiche solo quando cambia qualcosa (nuovi dispositivi, porte, problemi, CVE) e solo con conteggi. Icona nella barra dei menu e apertura all'accesso |
| **Rischio** | Punteggio 0–100 per host e per rete, voto A–F |
| **Storico** | Ogni scan viene salvato in `~/Library/Application Support/SubnetScout/Scans`. Il diff con lo scan precedente mostra nuovi dispositivi, porte aperte o chiuse e nuovi problemi |
| **Dispositivi noti** | I dispositivi segnati come noti spariscono dal badge «NUOVO» |
| **Report** | HTML autonomo (chiaro e scuro, stampabile in PDF dal browser), CSV per porta, JSON completo |

## Struttura

```
Sources/ScanKit/          motore, senza UI (testabile, riusabile da una CLI)
  ScanProfile.swift       profili → argomenti nmap, validazione dei target
  NmapRunner.swift        Process + XML su stdout, progresso, cancellazione, modalità admin
  NmapXMLParser.swift     parser SAX dell'output -oX
  NetworkInfo.swift       interfacce (getifaddrs), gateway, tabella ARP
  MACVendorDB.swift       lookup OUI (nmap-mac-prefixes)
  AuditEngine.swift       regole di audit → Finding
  DeviceKind.swift        classificazione euristica dei dispositivi
  ScanEngine.swift        orchestrazione: scan → parse → enrich → audit
  ScanDiff.swift          confronto tra scansioni
  ScanHistoryStore.swift  persistenza JSON
  ReportGenerator.swift   HTML e CSV
Sources/SubnetScout/      app SwiftUI
Tests/ScanKitTests/       Swift Testing con fixture XML + scan reale di localhost
```

## Roadmap

- [x] Privileged helper (`SMAppService` + XPC) con avanzamento e annullamento
- [x] Nomi e modelli da Bonjour/mDNS
- [x] Correlazione delle CVE dalle versioni dei servizi (API NVD, facoltativa)
- [ ] Export PDF nativo (WKWebView + NSPrintOperation)
- [x] Scansioni programmate e notifiche sui cambiamenti
- [x] App nella barra dei menu
- [ ] Mappa visuale della rete
- [ ] Discovery IPv6
- [ ] Controllo delle credenziali predefinite (separato, da attivare esplicitamente)
- [ ] Interfaccia in inglese
- [x] Icona dell'app
- [ ] Firma Developer ID e notarizzazione

## Licenza

MIT, vedi [LICENSE](LICENSE). nmap è distribuito separatamente con la propria licenza (NPSL).
