import Foundation

public struct NmapRun: Sendable {
    public var hosts: [Host]
    public var version: String?
    public var args: String?
    public var startedAt: Date?
    public var finishedAt: Date?
    /// Script eseguiti prima/dopo la scansione degli host (es. broadcast-dhcp-discover).
    public var runScripts: [ScriptOutput] = []
}

public enum NmapParseError: LocalizedError {
    case invalidXML(String)

    public var errorDescription: String? {
        switch self {
        case .invalidXML(let msg): "Invalid nmap XML output: \(msg)"
        }
    }
}

/// Parser SAX dell'output `-oX` di nmap. Restituisce solo gli host "up".
public enum NmapXMLParser {
    public static func parse(_ data: Data) throws -> NmapRun {
        let delegate = Delegate()
        let parser = XMLParser(data: data)
        parser.delegate = delegate
        // L'output -oX contiene un DOCTYPE: niente risoluzione di entità esterne.
        parser.shouldResolveExternalEntities = false
        if !parser.parse() {
            // Una scansione interrotta può lasciare l'XML troncato: se abbiamo
            // già host completi li teniamo, altrimenti è un errore.
            if delegate.hosts.isEmpty {
                throw NmapParseError.invalidXML(parser.parserError?.localizedDescription ?? "sconosciuto")
            }
        }
        return NmapRun(hosts: delegate.hosts, version: delegate.version, args: delegate.args,
                       startedAt: delegate.startedAt, finishedAt: delegate.finishedAt,
                       runScripts: delegate.runScripts)
    }

    private final class Delegate: NSObject, XMLParserDelegate {
        var hosts: [Host] = []
        var version: String?
        var args: String?
        var startedAt: Date?
        var finishedAt: Date?
        var runScripts: [ScriptOutput] = []

        private var inRunScript = false
        private var cpeText: String?
        private var host: Host?
        private var hostUp = false
        private var port: PortInfo?
        private var inHostScript = false

        func parser(_ parser: XMLParser, didStartElement name: String, namespaceURI: String?,
                    qualifiedName: String?, attributes a: [String: String]) {
            switch name {
            case "nmaprun":
                version = a["version"]
                args = a["args"]
                if let s = a["start"], let t = TimeInterval(s) { startedAt = Date(timeIntervalSince1970: t) }
            case "finished":
                if let s = a["time"], let t = TimeInterval(s) { finishedAt = Date(timeIntervalSince1970: t) }
            case "host":
                host = Host(ip: "")
                hostUp = false
            case "status" where host != nil:
                hostUp = a["state"] == "up"
            case "address" where host != nil:
                switch a["addrtype"] {
                case "ipv4", "ipv6":
                    host?.ip = a["addr"] ?? ""
                case "mac":
                    host?.mac = a["addr"]?.uppercased()
                    host?.vendor = a["vendor"]
                default: break
                }
            case "hostname":
                if let n = a["name"], !n.isEmpty, host?.hostnames.contains(n) == false {
                    host?.hostnames.append(n)
                }
            case "port":
                port = PortInfo(number: Int(a["portid"] ?? "") ?? 0, proto: a["protocol"] ?? "tcp", state: "unknown")
            case "state" where port != nil:
                port?.state = a["state"] ?? "unknown"
                port?.reason = a["reason"]
            case "cpe" where port?.service != nil:
                cpeText = ""
            case "service" where port != nil:
                port?.service = ServiceInfo(name: a["name"], product: a["product"], version: a["version"],
                                            extraInfo: a["extrainfo"], tunnel: a["tunnel"])
            case "hostscript":
                inHostScript = true
            case "prescript", "postscript":
                inRunScript = true
            case "script":
                guard let id = a["id"] else { break }
                let s = ScriptOutput(id: id, output: a["output"] ?? "")
                if port != nil {
                    port?.scripts.append(s)
                } else if inHostScript {
                    host?.hostScripts.append(s)
                } else if inRunScript {
                    runScripts.append(s)
                }
            case "osmatch":
                if let n = a["name"] {
                    host?.osGuesses.append(OSGuess(name: n, accuracy: Int(a["accuracy"] ?? "") ?? 0))
                }
            case "times":
                if let srtt = a["srtt"], let us = Double(srtt) { host?.latencyMs = us / 1000 }
            default:
                break
            }
        }

        func parser(_ parser: XMLParser, foundCharacters string: String) {
            if cpeText != nil { cpeText! += string }
        }

        func parser(_ parser: XMLParser, didEndElement name: String, namespaceURI: String?, qualifiedName: String?) {
            switch name {
            case "cpe":
                if let cpe = cpeText?.trimmingCharacters(in: .whitespacesAndNewlines), !cpe.isEmpty, port?.service != nil {
                    let existing = port?.service?.cpes ?? []
                    port?.service?.cpes = existing + [cpe]
                }
                cpeText = nil
            case "port":
                if let p = port { host?.ports.append(p) }
                port = nil
            case "hostscript":
                inHostScript = false
            case "prescript", "postscript":
                inRunScript = false
            case "host":
                if let h = host, hostUp, !h.ip.isEmpty { hosts.append(h) }
                host = nil
            default:
                break
            }
        }
    }
}
