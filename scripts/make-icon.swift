// Genera l'icona di SubnetScout (radar + nodi di rete) e la salva come .icns.
//
//   swift scripts/make-icon.swift            # → Resources/AppIcon.icns
//   swift scripts/make-icon.swift out.png    # → solo PNG 1024×1024 (anteprima)
//
// Disegnata interamente con CoreGraphics: niente asset binari da mantenere a mano.

import AppKit
import CoreGraphics

let size: CGFloat = 1024
// Griglia delle icone macOS: corpo 824×824 centrato, raggio d'angolo ~185.
let body = CGRect(x: 100, y: 100, width: 824, height: 824)
let corner: CGFloat = 185
let center = CGPoint(x: body.midX, y: body.midY)

func color(_ hex: UInt32, _ alpha: CGFloat = 1) -> CGColor {
    CGColor(srgbRed: CGFloat(hex >> 16 & 0xFF) / 255,
            green: CGFloat(hex >> 8 & 0xFF) / 255,
            blue: CGFloat(hex & 0xFF) / 255, alpha: alpha)
}

let mint: UInt32 = 0x5EF2C4
let orange: UInt32 = 0xFF9F43

func point(radius r: CGFloat, degrees a: CGFloat) -> CGPoint {
    let rad = a * .pi / 180
    return CGPoint(x: center.x + r * cos(rad), y: center.y + r * sin(rad))
}

func render() -> CGImage {
    let space = CGColorSpace(name: CGColorSpace.sRGB)!
    let ctx = CGContext(data: nil, width: Int(size), height: Int(size), bitsPerComponent: 8, bytesPerRow: 0,
                        space: space, bitmapInfo: CGImageAlphaInfo.premultipliedLast.rawValue)!
    let shape = CGPath(roundedRect: body, cornerWidth: corner, cornerHeight: corner, transform: nil)

    // Ombra del corpo
    ctx.saveGState()
    ctx.setShadow(offset: CGSize(width: 0, height: -12), blur: 28, color: color(0x000000, 0.35))
    ctx.addPath(shape)
    ctx.setFillColor(color(0x0B1E3A))
    ctx.fillPath()
    ctx.restoreGState()

    ctx.saveGState()
    ctx.addPath(shape)
    ctx.clip()

    // Sfondo: gradiente blu notte → petrolio
    let bg = CGGradient(colorsSpace: space, colors: [color(0x13305A), color(0x0A1A33), color(0x06303A)] as CFArray,
                        locations: [0, 0.55, 1])!
    ctx.drawLinearGradient(bg, start: CGPoint(x: body.minX, y: body.maxY), end: CGPoint(x: body.maxX, y: body.minY), options: [])

    // Bagliore centrale
    let glow = CGGradient(colorsSpace: space, colors: [color(mint, 0.18), color(mint, 0)] as CFArray, locations: [0, 1])!
    ctx.drawRadialGradient(glow, startCenter: center, startRadius: 0, endCenter: center, endRadius: 420, options: [])

    // Griglia: assi e anelli concentrici
    ctx.setLineCap(.round)
    ctx.setStrokeColor(color(mint, 0.13))
    ctx.setLineWidth(4)
    ctx.move(to: CGPoint(x: body.minX, y: center.y)); ctx.addLine(to: CGPoint(x: body.maxX, y: center.y))
    ctx.move(to: CGPoint(x: center.x, y: body.minY)); ctx.addLine(to: CGPoint(x: center.x, y: body.maxY))
    ctx.strokePath()
    for (r, a) in [(115.0, 0.30), (225.0, 0.26), (335.0, 0.22)] as [(CGFloat, CGFloat)] {
        ctx.setStrokeColor(color(mint, a))
        ctx.setLineWidth(6)
        ctx.addEllipse(in: CGRect(x: center.x - r, y: center.y - r, width: 2 * r, height: 2 * r))
        ctx.strokePath()
    }

    // Fascio di scansione: spicchi sempre più trasparenti dietro il bordo d'attacco
    let lead: CGFloat = 52       // angolo del bordo d'attacco (gradi, antiorario da destra)
    let trail: CGFloat = 75      // ampiezza della scia
    let steps = 90
    let sweepRadius: CGFloat = 420
    for i in 0..<steps {
        let t = CGFloat(i) / CGFloat(steps)
        let a0 = lead - trail * t
        let a1 = lead - trail * (t + 1 / CGFloat(steps))
        ctx.move(to: center)
        ctx.addArc(center: center, radius: sweepRadius, startAngle: a1 * .pi / 180, endAngle: a0 * .pi / 180, clockwise: false)
        ctx.closePath()
        ctx.setFillColor(color(mint, 0.55 * pow(1 - t, 1.8)))
        ctx.fillPath()
    }
    // Bordo d'attacco
    ctx.saveGState()
    ctx.setShadow(offset: .zero, blur: 18, color: color(mint, 0.9))
    ctx.setStrokeColor(color(0xC9FFF0))
    ctx.setLineWidth(9)
    ctx.move(to: center)
    ctx.addLine(to: point(radius: sweepRadius, degrees: lead))
    ctx.strokePath()
    ctx.restoreGState()

    // Nodi di rete e collegamenti
    let nodes: [(r: CGFloat, a: CGFloat, size: CGFloat, hot: Bool)] = [
        (225, 38, 30, false),   // appena «illuminato» dal fascio
        (335, 112, 24, false),
        (115, 160, 22, false),
        (290, 205, 26, true),   // problema trovato
        (225, 300, 24, false),
        (335, 338, 20, false),
    ]
    let pts = nodes.map { point(radius: $0.r, degrees: $0.a) }
    ctx.setStrokeColor(color(mint, 0.35))
    ctx.setLineWidth(5)
    for (a, b) in [(0, 1), (1, 2), (2, 3), (3, 4), (4, 5), (5, 0)] {
        ctx.move(to: pts[a]); ctx.addLine(to: pts[b])
    }
    ctx.strokePath()

    for (i, n) in nodes.enumerated() {
        let p = pts[i]
        let hex = n.hot ? orange : mint
        if n.hot {
            // alone pulsante attorno al nodo con problemi
            ctx.setStrokeColor(color(orange, 0.55))
            ctx.setLineWidth(6)
            let r = n.size + 26
            ctx.addEllipse(in: CGRect(x: p.x - r, y: p.y - r, width: 2 * r, height: 2 * r))
            ctx.strokePath()
        }
        ctx.saveGState()
        ctx.setShadow(offset: .zero, blur: n.hot || i == 0 ? 30 : 16, color: color(hex, 0.95))
        ctx.setFillColor(color(i == 0 ? 0xE6FFF8 : hex))
        ctx.fillEllipse(in: CGRect(x: p.x - n.size, y: p.y - n.size, width: 2 * n.size, height: 2 * n.size))
        ctx.restoreGState()
    }

    // Centro del radar
    ctx.saveGState()
    ctx.setShadow(offset: .zero, blur: 20, color: color(mint, 1))
    ctx.setFillColor(color(0xE6FFF8))
    ctx.fillEllipse(in: CGRect(x: center.x - 22, y: center.y - 22, width: 44, height: 44))
    ctx.restoreGState()

    // Riflesso in alto
    let gloss = CGGradient(colorsSpace: space, colors: [color(0xFFFFFF, 0.14), color(0xFFFFFF, 0)] as CFArray, locations: [0, 1])!
    ctx.drawLinearGradient(gloss, start: CGPoint(x: center.x, y: body.maxY), end: CGPoint(x: center.x, y: center.y + 60), options: [])
    ctx.restoreGState()

    // Bordo sottile
    ctx.addPath(shape)
    ctx.setStrokeColor(color(0xFFFFFF, 0.10))
    ctx.setLineWidth(3)
    ctx.strokePath()

    return ctx.makeImage()!
}

func writePNG(_ image: CGImage, to url: URL, pixels: Int) throws {
    let rep = NSBitmapImageRep(bitmapDataPlanes: nil, pixelsWide: pixels, pixelsHigh: pixels, bitsPerSample: 8,
                               samplesPerPixel: 4, hasAlpha: true, isPlanar: false, colorSpaceName: .deviceRGB,
                               bytesPerRow: 0, bitsPerPixel: 0)!
    NSGraphicsContext.saveGraphicsState()
    let g = NSGraphicsContext(bitmapImageRep: rep)!
    g.imageInterpolation = .high
    NSGraphicsContext.current = g
    g.cgContext.draw(image, in: CGRect(x: 0, y: 0, width: pixels, height: pixels))
    NSGraphicsContext.restoreGraphicsState()
    try rep.representation(using: .png, properties: [:])!.write(to: url)
}

let image = render()
let args = CommandLine.arguments.dropFirst()
if let out = args.first, out.hasSuffix(".png") {
    try writePNG(image, to: URL(fileURLWithPath: out), pixels: 1024)
    print("✓ \(out)")
    exit(0)
}

let output = URL(fileURLWithPath: args.first ?? "Resources/AppIcon.icns")
let iconset = FileManager.default.temporaryDirectory.appending(path: "AppIcon-\(UUID().uuidString).iconset")
try FileManager.default.createDirectory(at: iconset, withIntermediateDirectories: true)
defer { try? FileManager.default.removeItem(at: iconset) }
for base in [16, 32, 128, 256, 512] {
    try writePNG(image, to: iconset.appending(path: "icon_\(base)x\(base).png"), pixels: base)
    try writePNG(image, to: iconset.appending(path: "icon_\(base)x\(base)@2x.png"), pixels: base * 2)
}
let p = Process()
p.executableURL = URL(fileURLWithPath: "/usr/bin/iconutil")
p.arguments = ["-c", "icns", iconset.path, "-o", output.path]
try p.run()
p.waitUntilExit()
guard p.terminationStatus == 0 else { print("iconutil non riuscito"); exit(1) }
print("✓ \(output.path)")
