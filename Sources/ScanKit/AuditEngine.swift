import Foundation

/// Regole di audit applicate ai risultati di nmap. Ogni regola guarda porte aperte,
/// nomi dei servizi e output degli script NSE e produce dei `Finding`.
public enum AuditEngine {
    public static func audit(_ hosts: [Host], now: Date = Date()) -> [Finding] {
        var out: [String: Finding] = [:]
        for host in hosts {
            for f in auditHost(host, now: now) where out[f.id] == nil {
                out[f.id] = f
            }
        }
        return out.values.sorted {
            ($0.severity, $1.hostIP, $1.port ?? "") > ($1.severity, $0.hostIP, $0.port ?? "")
        }
    }

    static func auditHost(_ host: Host, now: Date) -> [Finding] {
        var f: [Finding] = []
        let ip = host.ip

        func add(_ rule: String, _ sev: Severity, _ title: String, _ detail: String, _ fix: String,
                 _ port: PortInfo? = nil, evidence: String? = nil) {
            f.append(Finding(ruleID: rule, severity: sev, title: title, detail: detail, remediation: fix,
                             hostIP: ip, port: port?.id, evidence: evidence))
        }

        for p in host.openPorts {
            let svc = p.serviceName
            let tcp = p.proto == "tcp"

            // --- Protocolli in chiaro / obsoleti
            if svc == "telnet" || (tcp && p.number == 23) {
                add("telnet", .high, "Telnet attivo",
                    "Telnet trasmette credenziali e sessione in chiaro.",
                    "Disabilita Telnet e usa SSH.", p)
            }
            if tcp, ["login", "shell", "exec"].contains(svc) || [512, 513, 514].contains(p.number) {
                add("r-services", .high, "Servizi r* (rsh/rlogin/rexec) attivi",
                    "Servizi legacy senza cifratura e con autenticazione debole.",
                    "Disattiva rsh/rlogin/rexec.", p)
            }
            if svc == "ftp" || (tcp && p.number == 21 && !(p.service?.isTLS ?? false)) {
                if let anon = p.script("ftp-anon"), anon.contains("Anonymous FTP login allowed") {
                    add("ftp-anon", .high, "FTP con accesso anonimo",
                        "Chiunque sulla rete può collegarsi al server FTP senza password.",
                        "Disabilita il login anonimo o il servizio FTP.", p, evidence: firstLines(anon))
                } else {
                    add("ftp", .medium, "FTP non cifrato",
                        "FTP invia nome utente e password in chiaro.",
                        "Usa SFTP o FTPS, oppure disattiva il servizio.", p)
                }
            }
            if ["pop3", "imap"].contains(svc), !(p.service?.isTLS ?? false) {
                add("mail-cleartext", .low, "Posta senza TLS (\(svc.uppercased()))",
                    "Il servizio di posta accetta connessioni non cifrate.",
                    "Abilita solo POP3S/IMAPS o STARTTLS obbligatorio.", p)
            }
            if svc == "mqtt" || (tcp && p.number == 1883) {
                add("mqtt", .medium, "Broker MQTT non cifrato",
                    "Tipico dei dispositivi IoT/domotica: messaggi e credenziali viaggiano in chiaro.",
                    "Usa MQTT su TLS (8883) e richiedi autenticazione.", p)
            }
            if svc == "tftp" || (p.proto == "udp" && p.number == 69) {
                add("tftp", .medium, "TFTP attivo",
                    "TFTP non ha autenticazione: chiunque può leggere (o scrivere) file.",
                    "Disattiva TFTP se non serve per provisioning.", p)
            }

            // --- Accesso remoto
            if svc == "ms-wbt-server" || (tcp && p.number == 3389) {
                let rdp = p.script("rdp-enum-encryption")
                if let rdp, !rdp.contains("CredSSP (NLA): SUCCESS") {
                    add("rdp-no-nla", .high, "RDP senza Network Level Authentication",
                        "Senza NLA il server espone la schermata di login prima dell'autenticazione.",
                        "Abilita NLA e limita RDP a VPN o host fidati.", p, evidence: firstLines(rdp))
                } else {
                    add("rdp", .medium, "Desktop remoto (RDP) esposto",
                        "RDP è un bersaglio frequente di brute force ed exploit.",
                        "Limita l'accesso tramite firewall/VPN e usa password robuste.", p)
                }
            }
            if svc.hasPrefix("vnc") || (tcp && (5900...5903).contains(p.number)) {
                if let vnc = p.script("vnc-info"), vnc.contains("None (1)") {
                    add("vnc-noauth", .critical, "VNC senza autenticazione",
                        "Il server VNC permette il controllo dello schermo senza password.",
                        "Imposta una password robusta o disattiva la condivisione schermo.", p, evidence: firstLines(vnc))
                } else {
                    add("vnc", .medium, "Condivisione schermo (VNC) esposta",
                        "VNC usa spesso password deboli e cifratura limitata.",
                        "Limita l'accesso a utenti/host specifici o usa una VPN.", p)
                }
            }
            if let v1 = p.script("sshv1"), v1.contains("SSHv1") {
                add("sshv1", .high, "SSH protocollo 1 supportato",
                    "SSHv1 ha vulnerabilità crittografiche note.",
                    "Configura il server per accettare solo SSHv2.", p)
            }
            if let algos = p.script("ssh2-enum-algos") {
                let weak = ["diffie-hellman-group1-sha1", "arcfour", "-cbc", "hmac-md5", "ssh-dss"]
                    .filter { algos.contains($0) }
                if !weak.isEmpty {
                    add("ssh-weak-algos", .low, "SSH accetta algoritmi deboli",
                        "Algoritmi obsoleti abilitati: \(weak.joined(separator: ", ")).",
                        "Rimuovi cifrari CBC, arcfour, hmac-md5 e DH group1 dalla configurazione SSH.", p)
                }
            }

            // --- Database e servizi che non dovrebbero essere esposti
            let databases: [Int: String] = [
                3306: "MySQL/MariaDB", 5432: "PostgreSQL", 1433: "Microsoft SQL Server", 1521: "Oracle",
                27017: "MongoDB", 6379: "Redis", 9200: "Elasticsearch", 11211: "Memcached", 5984: "CouchDB",
            ]
            let dbNames = ["mysql", "postgresql", "ms-sql-s", "oracle-tns", "mongodb", "mongod", "redis",
                           "memcache", "couchdb"]
            if tcp, let db = databases[p.number] ?? (dbNames.contains(svc) ? svc : nil) {
                add("db-exposed", .high, "Database raggiungibile in rete (\(db))",
                    "Il database accetta connessioni da altri dispositivi della rete.",
                    "Fai ascoltare il servizio solo su localhost o limita gli IP con il firewall.", p)
            }
            if tcp, p.number == 2375 || svc == "docker" {
                add("docker-api", .critical, "API Docker esposta senza TLS",
                    "Chi raggiunge la porta 2375 può avviare container come root sull'host.",
                    "Disabilita l'API TCP o proteggila con TLS (2376) e mutual auth.", p)
            }

            // --- Condivisioni Windows / NetBIOS
            if tcp, p.number == 139 || svc == "netbios-ssn" {
                add("netbios", .low, "NetBIOS attivo",
                    "NetBIOS espone nome macchina e informazioni di rete; protocollo legacy.",
                    "Disabilita NetBIOS over TCP/IP se non necessario.", p)
            }

            // --- Web senza HTTPS
            if tcp, svc == "http" || svc == "http-proxy" || svc == "http-alt", !(p.service?.isTLS ?? false) {
                let title = p.script("http-title").map { " (\(firstLines($0, max: 1)))" } ?? ""
                add("http-cleartext", .low, "Interfaccia web senza HTTPS\(title)",
                    "Se la pagina prevede un login, le credenziali viaggiano in chiaro.",
                    "Abilita HTTPS sul dispositivo o usa solo la versione cifrata.", p)
            }

            // --- TLS
            if let ciphers = p.script("ssl-enum-ciphers") {
                let old = ["SSLv3", "TLSv1.0", "TLSv1.1"].filter { ciphers.contains("\($0):") }
                if !old.isEmpty {
                    add("tls-old", .medium, "Protocolli TLS obsoleti",
                        "Il servizio accetta \(old.joined(separator: ", ")).",
                        "Abilita solo TLS 1.2 e 1.3.", p)
                }
                if let grade = leastStrength(ciphers), ["C", "D", "E", "F"].contains(grade) {
                    add("tls-weak-ciphers", grade == "C" ? .medium : .high, "Cifrari TLS deboli (grado \(grade))",
                        "nmap valuta il cifrario più debole accettato con grado \(grade).",
                        "Rimuovi cifrari RC4, 3DES, export e senza forward secrecy.", p)
                }
            }
            if let cert = p.script("ssl-cert") {
                if let expiry = certExpiry(cert) {
                    if expiry < now {
                        add("cert-expired", .medium, "Certificato TLS scaduto",
                            "Il certificato è scaduto il \(expiry.formatted(date: .abbreviated, time: .omitted)).",
                            "Rinnova il certificato.", p)
                    } else if expiry < now.addingTimeInterval(30 * 86400) {
                        add("cert-expiring", .low, "Certificato TLS in scadenza",
                            "Scade il \(expiry.formatted(date: .abbreviated, time: .omitted)).",
                            "Pianifica il rinnovo.", p)
                    }
                }
                if isSelfSigned(cert) {
                    add("cert-self-signed", .info, "Certificato self-signed",
                        "Normale per router e NAS, ma non protegge dal man-in-the-middle.",
                        "Usa un certificato di una CA interna o pubblica se possibile.", p)
                }
            }

            if let dh = p.script("ssl-dh-params"), dh.contains("VULNERABLE") {
                add("tls-weak-dh", .medium, "Parametri Diffie-Hellman deboli",
                    "Lo scambio di chiavi usa gruppi DH piccoli o comuni (attacchi tipo Logjam).",
                    "Usa gruppi DH da almeno 2048 bit oppure solo ECDHE.", p, evidence: firstLines(dh, max: 3))
            }

            // --- Web
            if let headers = p.script("http-security-headers"), headers.contains("HSTS not configured") {
                add("http-no-hsts", .low, "HTTPS senza HSTS",
                    "Il sito non impone HTTPS al browser: un attaccante in LAN può forzare la versione non cifrata (SSL stripping).",
                    "Abilita l'header Strict-Transport-Security, se il dispositivo lo consente.", p)
            }
            if let methods = p.script("http-methods"), let risky = riskyMethods(methods) {
                let writes = risky.filter { ["PUT", "DELETE", "MOVE", "COPY", "PROPPATCH", "MKCOL"].contains($0) }
                add("http-risky-methods", writes.isEmpty ? .low : .medium,
                    "Metodi HTTP rischiosi abilitati (\(risky.joined(separator: ", ")))",
                    writes.isEmpty
                        ? "TRACE può essere sfruttato per leggere cookie e header (cross-site tracing)."
                        : "Il server accetta metodi che possono modificare o cancellare file.",
                    "Disabilita i metodi non necessari nella configurazione del server web.", p)
            }

            // --- Chiavi SSH
            if let keys = p.script("ssh-hostkey") {
                let weak = weakHostKeys(keys)
                if !weak.isEmpty {
                    add("ssh-weak-hostkey", .low, "Chiavi host SSH deboli",
                        "Il server usa chiavi obsolete: \(weak.joined(separator: ", ")).",
                        "Rigenera le chiavi host (Ed25519 o RSA ≥ 3072 bit) e rimuovi DSA.", p)
                }
            }

            // --- UDP
            if svc == "snmp" || (p.proto == "udp" && p.number == 161) {
                if let info = p.script("snmp-info"), !info.isEmpty {
                    add("snmp-public", .high, "SNMP risponde con community predefinita",
                        "Il dispositivo restituisce informazioni con la community «public».",
                        "Cambia la community, limita gli IP o passa a SNMPv3.", p, evidence: firstLines(info))
                } else {
                    add("snmp", .medium, "SNMP attivo",
                        "SNMP v1/v2c usa community in chiaro.",
                        "Usa SNMPv3 o disattivalo se non serve.", p)
                }
            }
            if p.proto == "udp", p.number == 1900 || svc == "upnp" {
                add("upnp", .low, "UPnP/SSDP attivo",
                    "UPnP consente ai dispositivi di aprire porte sul router automaticamente.",
                    "Disattiva UPnP sul router se non indispensabile.", p)
            }
            if let rec = p.script("dns-recursion"), rec.contains("enabled") {
                add("dns-recursion", .info, "Resolver DNS ricorsivo",
                    "Normale in LAN; critico se la porta 53 è raggiungibile da Internet.",
                    "Verifica che il DNS non sia esposto all'esterno.", p)
            }
        }

        // --- Script a livello di host (SMB)
        if let smb = host.hostScript("smb-protocols"), smb.contains("SMBv1") {
            add("smbv1", .high, "SMBv1 abilitato",
                "SMBv1 è il protocollo sfruttato da WannaCry/EternalBlue.",
                "Disabilita SMBv1 sul dispositivo (spesso NAS o stampanti vecchie).",
                evidence: firstLines(smb))
        }
        if let mode = host.hostScript("smb2-security-mode"), mode.contains("not required") {
            add("smb-signing", .medium, "Firma SMB non obbligatoria",
                "Senza firma SMB sono possibili attacchi di relay NTLM.",
                "Imposta la firma SMB come obbligatoria.")
        }

        // --- Superficie d'attacco ampia
        let open = host.openPorts.count
        if open >= 20 {
            add("many-ports", .info, "Molte porte aperte (\(open))",
                "Un numero elevato di servizi aumenta la superficie d'attacco.",
                "Verifica quali servizi sono davvero necessari.")
        }
        return f
    }

    // MARK: - Helper di parsing script

    static func firstLines(_ s: String, max: Int = 4) -> String {
        s.split(separator: "\n").map { $0.trimmingCharacters(in: .whitespaces) }
            .filter { !$0.isEmpty }.prefix(max).joined(separator: " · ")
    }

    /// "Potentially risky methods: PUT DELETE TRACE" → ["PUT", "DELETE", "TRACE"]
    static func riskyMethods(_ s: String) -> [String]? {
        guard let r = s.range(of: "Potentially risky methods:") else { return nil }
        let line = s[r.upperBound...].prefix { $0 != "\n" }
        let methods = line.split(separator: " ").map(String.init).filter { !$0.isEmpty }
        return methods.isEmpty ? nil : methods
    }

    /// Righe "1024 aa:bb:… (DSA)" / "2048 SHA256:… (RSA)": DSA sempre, RSA sotto 2048 bit.
    static func weakHostKeys(_ s: String) -> [String] {
        s.split(separator: "\n").compactMap { raw in
            let parts = raw.trimmingCharacters(in: .whitespaces).split(separator: " ")
            guard parts.count >= 3, let bits = Int(parts[0]), let type = parts.last?.trimmingCharacters(in: CharacterSet(charactersIn: "()")) else { return nil }
            if type == "DSA" || (type == "RSA" && bits < 2048) { return "\(type) \(bits) bit" }
            return nil
        }
    }

    static func leastStrength(_ s: String) -> String? {
        guard let r = s.range(of: "least strength: ") else { return nil }
        return s[r.upperBound...].first.map(String.init)
    }

    static func certExpiry(_ s: String) -> Date? {
        guard let r = s.range(of: "Not valid after:") else { return nil }
        let rest = s[r.upperBound...].trimmingCharacters(in: .whitespaces)
        let day = String(rest.prefix(10)) // "2025-06-01"
        let f = DateFormatter()
        f.locale = Locale(identifier: "en_US_POSIX")
        f.timeZone = TimeZone(identifier: "UTC")
        f.dateFormat = "yyyy-MM-dd"
        return f.date(from: day)
    }

    static func isSelfSigned(_ s: String) -> Bool {
        func value(_ key: String) -> String? {
            s.split(separator: "\n").first { $0.trimmingCharacters(in: .whitespaces).hasPrefix(key) }
                .map { $0.trimmingCharacters(in: .whitespaces).dropFirst(key.count).trimmingCharacters(in: .whitespaces) }
        }
        guard let subject = value("Subject:"), let issuer = value("Issuer:") else { return false }
        return subject == issuer
    }
}
