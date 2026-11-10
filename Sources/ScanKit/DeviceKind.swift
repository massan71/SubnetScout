import Foundation

/// Classificazione euristica del dispositivo da produttore, hostname, porte e OS.
public enum DeviceKind: String, Codable, Sendable, CaseIterable {
    case router, mac, computer, phone, printer, nas, camera, tv, speaker, iot, server, virtualMachine, unknown

    public var label: String {
        switch self {
        case .router: "Router / rete"
        case .mac: "Mac"
        case .computer: "Computer"
        case .phone: "Smartphone / tablet"
        case .printer: "Stampante"
        case .nas: "NAS"
        case .camera: "Telecamera"
        case .tv: "TV / media"
        case .speaker: "Speaker"
        case .iot: "IoT / domotica"
        case .server: "Server"
        case .virtualMachine: "Macchina virtuale"
        case .unknown: "Sconosciuto"
        }
    }

    public var symbol: String {
        switch self {
        case .router: "wifi.router"
        case .mac: "desktopcomputer"
        case .computer: "pc"
        case .phone: "iphone"
        case .printer: "printer"
        case .nas: "externaldrive.connected.to.line.below"
        case .camera: "web.camera"
        case .tv: "tv"
        case .speaker: "hifispeaker"
        case .iot: "lightbulb"
        case .server: "server.rack"
        case .virtualMachine: "shippingbox"
        case .unknown: "questionmark.circle"
        }
    }
}

extension Host {
    public var kind: DeviceKind {
        if isGateway { return .router }
        // I servizi Bonjour sono il segnale più affidabile: li annuncia il dispositivo stesso.
        let bj = Set(bonjourServices ?? [])
        let m = (model ?? "").lowercased()
        if !bj.isDisjoint(with: ["_ipp._tcp", "_ipps._tcp", "_printer._tcp", "_pdl-datastream._tcp", "_uscan._tcp"]) { return .printer }
        if m.hasPrefix("iphone") || m.hasPrefix("ipad") { return .phone }
        if m.hasPrefix("mac") || m.hasPrefix("imac") { return .mac }
        if m.contains("appletv") || m.contains("tv") || bj.contains("_googlecast._tcp") || bj.contains("_androidtvremote2._tcp") { return .tv }
        if bj.contains("_sonos._tcp") || bj.contains("_spotify-connect._tcp") && !bj.contains("_googlecast._tcp") { return .speaker }
        if !bj.isDisjoint(with: ["_hap._tcp", "_homekit._tcp", "_matter._tcp", "_matterc._udp", "_shelly._tcp",
                                  "_esphomelib._tcp", "_hue._tcp", "_home-assistant._tcp"]) { return .iot }
        if bj.contains("_adisk._tcp") || bj.contains("_afpovertcp._tcp") && !bj.contains("_companion-link._tcp") { return .nas }
        let v = (vendor ?? "").lowercased()
        let h = hostnames.joined(separator: " ").lowercased()
        let os = (bestOSGuess?.name ?? "").lowercased()
        let svcs = Set(openPorts.map(\.serviceName))
        func any(_ words: [String], in s: String) -> Bool { words.contains { s.contains($0) } }

        if any(["iphone", "ipad", "android", "galaxy", "pixel"], in: h) { return .phone }
        if any(["macbook", "imac", "mac-mini", "macmini", "mac-studio"], in: h) || os.contains("macos") { return .mac }
        if any(["printer", "laserjet", "officejet", "epson", "brother", "canon"], in: h + v)
            || hasOpen(9100) || hasOpen(631) || svcs.contains("ipp") { return .printer }
        if any(["synology", "qnap", "nas", "truenas", "unraid"], in: h + v) { return .nas }
        if any(["hikvision", "dahua", "reolink", "axis comm", "camera", "cam-"], in: h + v) || hasOpen(554) { return .camera }
        if any(["sonos", "bose", "homepod", "echo"], in: h + v) { return .speaker }
        if any(["appletv", "apple-tv", "roku", "chromecast", "samsung electronics", "lg electronics", "tv"], in: h + v) { return .tv }
        if any(["vmware", "parallels", "qemu", "xensource", "proxmox", "virtualbox"], in: v) { return .virtualMachine }
        if any(["espressif", "tuya", "shelly", "philips lighting", "signify", "nest", "ring", "tp-link", "xiaomi"], in: v) { return .iot }
        if any(["ubiquiti", "netgear", "mikrotik", "cisco", "juniper", "aruba", "zyxel", "fritz", "avm", "firewalla"], in: v) { return .router }
        if v.contains("randomizzato") { return .phone }
        if os.contains("windows") || svcs.contains("microsoft-ds") || svcs.contains("ms-wbt-server") { return .computer }
        if v.contains("apple") { return .mac }
        if os.contains("linux") || svcs.contains("ssh") { return .server }
        return .unknown
    }
}
