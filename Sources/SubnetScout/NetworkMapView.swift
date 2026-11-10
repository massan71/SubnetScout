import SwiftUI
import ScanKit

/// "Map" tab: the gateway in the middle, devices grouped by type around it.
/// Click a node to open its details; drag to pan, pinch or use the buttons to zoom.
struct NetworkMapView: View {
    @Environment(AppModel.self) private var model
    let result: ScanResult

    @State private var zoom: CGFloat = 1
    @State private var pan: CGSize = .zero
    @State private var panStart: CGSize = .zero
    @State private var zoomStart: CGFloat = 1
    @State private var hovered: String?
    @State private var showAllNames = false
    @State private var onlyIssues = false

    var body: some View {
        let map = NetworkMap(result: result)
        let hosts = Dictionary(result.hosts.map { ($0.ip, $0) }, uniquingKeysWith: { a, _ in a })

        GeometryReader { geo in
            let unit = min(geo.size.width, geo.size.height) / 2 / 1.95 * zoom
            let c = CGPoint(x: geo.size.width / 2 + pan.width, y: geo.size.height / 2 + pan.height)
            let point = { (x: Double, y: Double) in CGPoint(x: c.x + x * unit, y: c.y - y * unit) }

            ZStack {
                Canvas { ctx, _ in
                    // Faint sector wedges, one per device type.
                    for g in map.groups {
                        var wedge = Path()
                        wedge.move(to: c)
                        wedge.addArc(center: c, radius: unit * 1.45,
                                     startAngle: .radians(-g.startAngle), endAngle: .radians(-g.endAngle), clockwise: true)
                        wedge.closeSubpath()
                        ctx.fill(wedge, with: .color(.secondary.opacity(0.06)))
                    }
                    // Links to the gateway (logical, not physical cabling).
                    for n in map.nodes {
                        var line = Path()
                        line.move(to: c)
                        line.addLine(to: point(n.x, n.y))
                        let relevant = (n.severity ?? .info) >= .medium
                        ctx.stroke(line, with: .color(relevant ? color(for: n).opacity(0.55) : .secondary.opacity(0.18)),
                                   lineWidth: relevant ? 1.5 : 0.8)
                    }
                }

                ForEach(map.groups, id: \.kind) { g in
                    Text("\(g.kind.label) (\(g.count))")
                        .font(.caption.weight(.semibold))
                        .foregroundStyle(.secondary)
                        .fixedSize()
                        .position(point(g.labelX, g.labelY))
                }

                if let center = map.center {
                    nodeView(center, host: hosts[center.ip], size: 46).position(c)
                } else {
                    Label("Network", systemImage: "network").font(.caption).position(c)
                }
                ForEach(map.nodes) { n in
                    nodeView(n, host: hosts[n.ip], size: 30).position(point(n.x, n.y))
                }
                // Names on their own layer, above every node, so no circle covers them.
                ForEach(placeLabels(map, center: c, point: point), id: \.node.ip) { item in
                    nameLabel(item.node).position(item.at)
                }
            }
            .contentShape(Rectangle())
            .gesture(
                DragGesture()
                    .onChanged { pan = CGSize(width: panStart.width + $0.translation.width,
                                              height: panStart.height + $0.translation.height) }
                    .onEnded { _ in panStart = pan }
            )
            .simultaneousGesture(
                MagnifyGesture()
                    .onChanged { zoom = min(4, max(0.4, zoomStart * $0.magnification)) }
                    .onEnded { _ in zoomStart = zoom }
            )
        }
        .overlay(alignment: .topTrailing) { controls }
        .overlay(alignment: .bottomLeading) { legend }
        .clipped()
    }

    // MARK: Node

    @ViewBuilder
    private func nodeView(_ n: NetworkMap.Node, host: Host?, size: CGFloat) -> some View {
        let selected = model.selectedHostID == n.ip
        let isNew = host.map { !model.isTrusted($0) } ?? false
        let relevant = (n.severity ?? .info) >= .medium
        ZStack {
                Circle()
                    .fill(Color(nsColor: .windowBackgroundColor))
                Circle()
                    .strokeBorder(color(for: n), lineWidth: selected ? 4 : 2.5)
                if isNew {
                    Circle()
                        .stroke(.orange, style: StrokeStyle(lineWidth: 1.5, dash: [3, 2]))
                        .padding(-5)
                }
                Image(systemName: n.isLocalMachine ? "laptopcomputer" : n.kind.symbol)
                    .font(.system(size: size * 0.42))
                    .foregroundStyle(.primary)
                if n.isUPnPGateway {
                    Image(systemName: "arrow.up.forward.circle.fill")
                        .font(.system(size: size * 0.38))
                        .foregroundStyle(.orange, .background)
                        .offset(x: size * 0.38, y: -size * 0.38)
                        .help("UPnP enabled: devices can open ports to the Internet")
                }
            }
        .frame(width: size, height: size)
        .opacity(onlyIssues && !relevant && !n.isGateway ? 0.25 : 1)
        .contentShape(Rectangle())
        .onTapGesture { model.selectedHostID = n.ip }
        .onHover { inside in hovered = inside ? n.ip : (hovered == n.ip ? nil : hovered) }
        .help("\(n.label) · \(n.ip) · \(n.kind.label)\(n.openPorts > 0 ? " · \(n.openPorts) open ports" : "")")
    }

    private func showsName(_ n: NetworkMap.Node) -> Bool {
        showAllNames || model.selectedHostID == n.ip || hovered == n.ip || n.isGateway || (n.severity ?? .info) >= .medium
    }

    /// Places the visible names greedily, most important first (selected, hovered,
    /// gateway, then by severity): a name goes below its node, or above it when that
    /// spot is taken, and is skipped when both collide with names already placed.
    private func placeLabels(_ map: NetworkMap, center c: CGPoint,
                             point: (Double, Double) -> CGPoint) -> [(node: NetworkMap.Node, at: CGPoint)] {
        func priority(_ n: NetworkMap.Node) -> Int {
            if model.selectedHostID == n.ip { return 100 }
            if hovered == n.ip { return 90 }
            if n.isGateway { return 80 }
            return (n.severity ?? .info).rawValue * 10 + (n.isUPnPGateway ? 5 : 0)
        }
        let candidates = map.allNodes.filter(showsName).sorted { priority($0) > priority($1) }
        var taken: [CGRect] = []
        var out: [(node: NetworkMap.Node, at: CGPoint)] = []
        for n in candidates {
            let size: CGFloat = n.isGateway ? 46 : 30
            let p = n.isGateway ? c : point(n.x, n.y)
            let text = n.isLocalMachine ? "\(n.label) (this Mac)" : n.label
            let w = min(140, CGFloat(text.count) * 6 + 12), h: CGFloat = 16
            let spots = [CGPoint(x: p.x, y: p.y + size / 2 + 11), CGPoint(x: p.x, y: p.y - size / 2 - 11)]
            let forced = priority(n) >= 80   // selected, hovered and gateway are always shown
            for (i, spot) in spots.enumerated() {
                let rect = CGRect(x: spot.x - w / 2, y: spot.y - h / 2, width: w, height: h)
                if !taken.contains(where: { $0.intersects(rect) }) || (forced && i == spots.count - 1) {
                    taken.append(rect)
                    out.append((n, spot))
                    break
                }
            }
        }
        return out
    }

    private func nameLabel(_ n: NetworkMap.Node) -> some View {
        Text(n.isLocalMachine ? "\(n.label) (this Mac)" : n.label)
            .font(.caption2)
            .lineLimit(1)
            .frame(maxWidth: 130)
            .padding(.horizontal, 5)
            .padding(.vertical, 1)
            .background(.regularMaterial, in: Capsule())
            .opacity(onlyIssues && (n.severity ?? .info) < .medium && !n.isGateway ? 0.25 : 1)
            .allowsHitTesting(false)
    }

    /// Ring color: severity of the worst finding, green when audited and clean, grey otherwise.
    private func color(for n: NetworkMap.Node) -> Color {
        if let s = n.severity, s > .info { return s.color }
        return result.profile.scansPorts ? .green : .gray
    }

    // MARK: Overlays

    private var controls: some View {
        HStack(spacing: 8) {
            Toggle("All names", isOn: $showAllNames).toggleStyle(.checkbox)
            Toggle("Only with issues", isOn: $onlyIssues).toggleStyle(.checkbox)
            Divider().frame(height: 16)
            Button { setZoom(zoom / 1.25) } label: { Image(systemName: "minus.magnifyingglass") }
                .help("Zoom out")
            Button { setZoom(zoom * 1.25) } label: { Image(systemName: "plus.magnifyingglass") }
                .help("Zoom in")
            Button { zoom = 1; zoomStart = 1; pan = .zero; panStart = .zero } label: {
                Image(systemName: "arrow.up.left.and.down.right.magnifyingglass")
            }
            .help("Fit")
        }
        .controlSize(.small)
        .padding(8)
        .background(.regularMaterial, in: RoundedRectangle(cornerRadius: 8))
        .padding(10)
    }

    private func setZoom(_ z: CGFloat) {
        zoom = min(4, max(0.4, z))
        zoomStart = zoom
    }

    private var legend: some View {
        HStack(spacing: 12) {
            legendItem(.green, "No issues")
            ForEach([Severity.low, .medium, .high, .critical], id: \.self) { legendItem($0.color, $0.label) }
            HStack(spacing: 4) {
                Circle().stroke(.orange, style: StrokeStyle(lineWidth: 1.5, dash: [3, 2])).frame(width: 12, height: 12)
                Text("New")
            }
            Text("Links are logical (via the gateway), not physical cabling.")
                .foregroundStyle(.secondary)
        }
        .font(.caption)
        .padding(8)
        .background(.regularMaterial, in: RoundedRectangle(cornerRadius: 8))
        .padding(10)
    }

    private func legendItem(_ color: Color, _ text: String) -> some View {
        HStack(spacing: 4) {
            Circle().strokeBorder(color, lineWidth: 2.5).frame(width: 12, height: 12)
            Text(text)
        }
    }
}
