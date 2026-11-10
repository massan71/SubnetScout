import Foundation

/// Geometry of the network map, shared by the app view and the HTML report.
///
/// nmap cannot see the physical topology (which switch or access point a device is
/// plugged into), so the map is a star around the gateway with devices grouped by
/// type in angular sectors. Coordinates are in unit space: the gateway is at (0, 0)
/// and devices sit on rings of radius ~1.
public struct NetworkMap: Sendable {
    public struct Node: Sendable, Identifiable, Hashable {
        public var id: String { ip }
        public let ip: String
        public let label: String
        public let kind: DeviceKind
        public let x: Double
        public let y: Double
        /// Most severe finding on the device (nil = no findings).
        public let severity: Severity?
        public let isGateway: Bool
        public let isLocalMachine: Bool
        /// The device is a UPnP Internet Gateway Device (can open ports to the Internet).
        public let isUPnPGateway: Bool
        public let openPorts: Int
    }

    public struct Group: Sendable, Hashable {
        public let kind: DeviceKind
        public let count: Int
        /// Sector in radians (0 = right, counter-clockwise).
        public let startAngle: Double
        public let endAngle: Double
        public let labelX: Double
        public let labelY: Double
    }

    public let center: Node?
    public let nodes: [Node]
    public let groups: [Group]

    /// Order of the sectors around the gateway: infrastructure first, personal devices last.
    static let kindOrder: [DeviceKind] = [.router, .server, .virtualMachine, .nas, .computer, .mac,
                                          .printer, .tv, .speaker, .camera, .iot, .phone, .unknown]

    static let innerRadius = 1.0
    static let outerRadius = 1.3
    static let labelRadius = 1.62
    /// Above this many devices per radian a group uses two staggered rings.
    static let densityForTwoRings = 6.0

    public init(result: ScanResult) {
        let worst = Dictionary(grouping: result.findings, by: \.hostIP).mapValues { $0.map(\.severity).max() }
        let upnp = Set(result.network?.upnpGateways.map(\.ip) ?? [])

        func node(_ h: Host, x: Double, y: Double) -> Node {
            Node(ip: h.ip, label: h.displayName, kind: h.kind, x: x, y: y, severity: worst[h.ip] ?? nil,
                 isGateway: h.isGateway, isLocalMachine: h.isLocalMachine, isUPnPGateway: upnp.contains(h.ip),
                 openPorts: h.openPorts.count)
        }

        let gatewayHost = result.hosts.first(where: \.isGateway)
        center = gatewayHost.map { node($0, x: 0, y: 0) }

        let others = result.hosts.filter { !$0.isGateway }
        let byKind = Dictionary(grouping: others, by: \.kind)
        let kinds = Self.kindOrder.filter { byKind[$0]?.isEmpty == false }
        let total = max(1, others.count)

        // Each sector gets an angle proportional to its size, with a minimum so that
        // a group of one is still readable; then everything is rescaled to 2π.
        let gap = kinds.count > 1 ? 0.06 : 0
        let minShare = 0.35
        let raw = kinds.map { max(Double(byKind[$0]!.count) / Double(total) * 2 * .pi, minShare) }
        let available = 2 * .pi - gap * Double(kinds.count)
        let scale = available / max(raw.reduce(0, +), 0.0001)

        var nodes: [Node] = []
        var groups: [Group] = []
        var angle = Double.pi / 2   // start at the top
        for (i, kind) in kinds.enumerated() {
            let members = byKind[kind]!.sorted { $0.ipSortKey < $1.ipSortKey }
            let span = raw[i] * scale
            let twoRings = Double(members.count) / span > Self.densityForTwoRings
            for (j, h) in members.enumerated() {
                let t = members.count == 1 ? 0.5 : (Double(j) + 0.5) / Double(members.count)
                let a = angle + span * t
                let r = twoRings && j % 2 == 1 ? Self.outerRadius : Self.innerRadius
                nodes.append(node(h, x: r * cos(a), y: r * sin(a)))
            }
            let mid = angle + span / 2
            groups.append(Group(kind: kind, count: members.count, startAngle: angle, endAngle: angle + span,
                                labelX: Self.labelRadius * cos(mid), labelY: Self.labelRadius * sin(mid)))
            angle += span + gap
        }
        self.nodes = nodes
        self.groups = groups
    }

    /// Every node, gateway included.
    public var allNodes: [Node] { (center.map { [$0] } ?? []) + nodes }
}
