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
                add("telnet", .high, "Telnet enabled",
                    "Telnet sends credentials and the whole session in cleartext.",
                    "Disable Telnet and use SSH.", p)
            }
            if tcp, ["login", "shell", "exec"].contains(svc) || [512, 513, 514].contains(p.number) {
                add("r-services", .high, "r* services (rsh/rlogin/rexec) enabled",
                    "Legacy services without encryption and with weak authentication.",
                    "Disable rsh/rlogin/rexec.", p)
            }
            if svc == "ftp" || (tcp && p.number == 21 && !(p.service?.isTLS ?? false)) {
                if let anon = p.script("ftp-anon"), anon.contains("Anonymous FTP login allowed") {
                    add("ftp-anon", .high, "FTP with anonymous access",
                        "Anyone on the network can log in to the FTP server without a password.",
                        "Disable anonymous login or the FTP service.", p, evidence: firstLines(anon))
                } else {
                    add("ftp", .medium, "Unencrypted FTP",
                        "FTP sends username and password in cleartext.",
                        "Use SFTP or FTPS, or disable the service.", p)
                }
            }
            if ["pop3", "imap"].contains(svc), !(p.service?.isTLS ?? false) {
                add("mail-cleartext", .low, "Mail without TLS (\(svc.uppercased()))",
                    "The mail service accepts unencrypted connections.",
                    "Allow only POP3S/IMAPS or require STARTTLS.", p)
            }
            if svc == "mqtt" || (tcp && p.number == 1883) {
                add("mqtt", .medium, "Unencrypted MQTT broker",
                    "Common on IoT/smart home devices: messages and credentials travel in cleartext.",
                    "Use MQTT over TLS (8883) and require authentication.", p)
            }
            if svc == "tftp" || (p.proto == "udp" && p.number == 69) {
                add("tftp", .medium, "TFTP enabled",
                    "TFTP has no authentication: anyone can read (or write) files.",
                    "Disable TFTP unless it is needed for provisioning.", p)
            }

            // --- Accesso remoto
            if svc == "ms-wbt-server" || (tcp && p.number == 3389) {
                let rdp = p.script("rdp-enum-encryption")
                if let rdp, !rdp.contains("CredSSP (NLA): SUCCESS") {
                    add("rdp-no-nla", .high, "RDP without Network Level Authentication",
                        "Without NLA the server exposes the login screen before authentication.",
                        "Enable NLA and restrict RDP to a VPN or trusted hosts.", p, evidence: firstLines(rdp))
                } else {
                    add("rdp", .medium, "Remote Desktop (RDP) exposed",
                        "RDP is a frequent target of brute-force attacks and exploits.",
                        "Restrict access with a firewall/VPN and use strong passwords.", p)
                }
            }
            if svc.hasPrefix("vnc") || (tcp && (5900...5903).contains(p.number)) {
                if let vnc = p.script("vnc-info"), vnc.contains("None (1)") {
                    add("vnc-noauth", .critical, "VNC without authentication",
                        "The VNC server allows screen control without a password.",
                        "Set a strong password or turn off screen sharing.", p, evidence: firstLines(vnc))
                } else {
                    add("vnc", .medium, "Screen sharing (VNC) exposed",
                        "VNC often uses weak passwords and limited encryption.",
                        "Restrict access to specific users/hosts or use a VPN.", p)
                }
            }
            if let v1 = p.script("sshv1"), v1.contains("SSHv1") {
                add("sshv1", .high, "SSH protocol 1 supported",
                    "SSHv1 has known cryptographic weaknesses.",
                    "Configure the server to accept SSHv2 only.", p)
            }
            if let algos = p.script("ssh2-enum-algos") {
                let weak = ["diffie-hellman-group1-sha1", "arcfour", "-cbc", "hmac-md5", "ssh-dss"]
                    .filter { algos.contains($0) }
                if !weak.isEmpty {
                    add("ssh-weak-algos", .low, "SSH accepts weak algorithms",
                        "Obsolete algorithms enabled: \(weak.joined(separator: ", ")).",
                        "Remove CBC ciphers, arcfour, hmac-md5 and DH group1 from the SSH configuration.", p)
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
                add("db-exposed", .high, "Database reachable on the network (\(db))",
                    "The database accepts connections from other devices on the network.",
                    "Make the service listen on localhost only, or restrict IPs with the firewall.", p)
            }
            if tcp, p.number == 2375 || svc == "docker" {
                add("docker-api", .critical, "Docker API exposed without TLS",
                    "Anyone who reaches port 2375 can start containers as root on the host.",
                    "Disable the TCP API or protect it with TLS (2376) and mutual auth.", p)
            }

            // --- Condivisioni Windows / NetBIOS
            if tcp, p.number == 139 || svc == "netbios-ssn" {
                add("netbios", .low, "NetBIOS enabled",
                    "NetBIOS exposes the machine name and network information; it is a legacy protocol.",
                    "Disable NetBIOS over TCP/IP if it is not needed.", p)
            }

            // --- Web senza HTTPS
            if tcp, svc == "http" || svc == "http-proxy" || svc == "http-alt", !(p.service?.isTLS ?? false) {
                let title = p.script("http-title").map { " (\(firstLines($0, max: 1)))" } ?? ""
                add("http-cleartext", .low, "Web interface without HTTPS\(title)",
                    "If the page has a login, credentials travel in cleartext.",
                    "Enable HTTPS on the device or use only the encrypted version.", p)
            }

            // --- TLS
            if let ciphers = p.script("ssl-enum-ciphers") {
                let old = ["SSLv3", "TLSv1.0", "TLSv1.1"].filter { ciphers.contains("\($0):") }
                if !old.isEmpty {
                    add("tls-old", .medium, "Obsolete TLS protocols",
                        "The service accepts \(old.joined(separator: ", ")).",
                        "Allow only TLS 1.2 and 1.3.", p)
                }
                if let grade = leastStrength(ciphers), ["C", "D", "E", "F"].contains(grade) {
                    add("tls-weak-ciphers", grade == "C" ? .medium : .high, "Weak TLS ciphers (grade \(grade))",
                        "nmap rates the weakest accepted cipher as grade \(grade).",
                        "Remove RC4, 3DES, export and non-forward-secret ciphers.", p)
                }
            }
            if let cert = p.script("ssl-cert") {
                if let expiry = certExpiry(cert) {
                    if expiry < now {
                        add("cert-expired", .medium, "Expired TLS certificate",
                            "The certificate expired on \(expiry.formatted(date: .abbreviated, time: .omitted)).",
                            "Renew the certificate.", p)
                    } else if expiry < now.addingTimeInterval(30 * 86400) {
                        add("cert-expiring", .low, "TLS certificate expiring soon",
                            "It expires on \(expiry.formatted(date: .abbreviated, time: .omitted)).",
                            "Plan the renewal.", p)
                    }
                }
                if isSelfSigned(cert) {
                    add("cert-self-signed", .info, "Self-signed certificate",
                        "Normal for routers and NAS devices, but it does not protect against man-in-the-middle attacks.",
                        "Use a certificate from an internal or public CA if possible.", p)
                }
            }

            if let dh = p.script("ssl-dh-params"), dh.contains("VULNERABLE") {
                add("tls-weak-dh", .medium, "Weak Diffie-Hellman parameters",
                    "Key exchange uses small or common DH groups (Logjam-style attacks).",
                    "Use DH groups of at least 2048 bits, or ECDHE only.", p, evidence: firstLines(dh, max: 3))
            }

            // --- Web
            if let headers = p.script("http-security-headers"), headers.contains("HSTS not configured") {
                add("http-no-hsts", .low, "HTTPS without HSTS",
                    "The site does not force HTTPS in the browser: an attacker on the LAN can force the unencrypted version (SSL stripping).",
                    "Enable the Strict-Transport-Security header, if the device allows it.", p)
            }
            if let methods = p.script("http-methods"), let risky = riskyMethods(methods) {
                let writes = risky.filter { ["PUT", "DELETE", "MOVE", "COPY", "PROPPATCH", "MKCOL"].contains($0) }
                add("http-risky-methods", writes.isEmpty ? .low : .medium,
                    "Risky HTTP methods enabled (\(risky.joined(separator: ", ")))",
                    writes.isEmpty
                        ? "TRACE can be abused to read cookies and headers (cross-site tracing)."
                        : "The server accepts methods that can modify or delete files.",
                    "Disable unneeded methods in the web server configuration.", p)
            }

            // --- Chiavi SSH
            if let keys = p.script("ssh-hostkey") {
                let weak = weakHostKeys(keys)
                if !weak.isEmpty {
                    add("ssh-weak-hostkey", .low, "Weak SSH host keys",
                        "The server uses obsolete keys: \(weak.joined(separator: ", ")).",
                        "Regenerate the host keys (Ed25519 or RSA ≥ 3072 bits) and remove DSA.", p)
                }
            }

            // --- UDP
            if svc == "snmp" || (p.proto == "udp" && p.number == 161) {
                if let info = p.script("snmp-info"), !info.isEmpty {
                    add("snmp-public", .high, "SNMP answers with the default community",
                        "The device returns information with the “public” community.",
                        "Change the community, restrict IPs or move to SNMPv3.", p, evidence: firstLines(info))
                } else {
                    add("snmp", .medium, "SNMP enabled",
                        "SNMP v1/v2c uses cleartext communities.",
                        "Use SNMPv3, or disable it if not needed.", p)
                }
            }
            if p.proto == "udp", p.number == 1900 || svc == "upnp" {
                add("upnp", .low, "UPnP/SSDP enabled",
                    "UPnP lets devices open ports on the router automatically.",
                    "Disable UPnP on the router unless it is essential.", p)
            }
            if let rec = p.script("dns-recursion"), rec.contains("enabled") {
                add("dns-recursion", .info, "Recursive DNS resolver",
                    "Normal on a LAN; critical if port 53 is reachable from the Internet.",
                    "Check that the DNS server is not exposed to the outside.", p)
            }
        }

        // --- Script a livello di host (SMB)
        if let smb = host.hostScript("smb-protocols"), smb.contains("SMBv1") {
            add("smbv1", .high, "SMBv1 enabled",
                "SMBv1 is the protocol exploited by WannaCry/EternalBlue.",
                "Disable SMBv1 on the device (often an old NAS or printer).",
                evidence: firstLines(smb))
        }
        if let mode = host.hostScript("smb2-security-mode"), mode.contains("not required") {
            add("smb-signing", .medium, "SMB signing not required",
                "Without SMB signing, NTLM relay attacks are possible.",
                "Make SMB signing mandatory.")
        }

        // --- Superficie d'attacco ampia
        let open = host.openPorts.count
        if open >= 20 {
            add("many-ports", .info, "Many open ports (\(open))",
                "A large number of services increases the attack surface.",
                "Check which services are really needed.")
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
