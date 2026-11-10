import SwiftUI
import ScanKit

/// Foundation ha già una classe `Host`: nell'app usiamo sempre quella di ScanKit.
typealias Host = ScanKit.Host

extension Severity {
    var color: Color {
        switch self {
        case .info: .gray
        case .low: .blue
        case .medium: .yellow
        case .high: .orange
        case .critical: .red
        }
    }
}

struct SeverityPill: View {
    let severity: Severity
    let text: String

    var body: some View {
        Text(text)
            .font(.caption.bold())
            .monospacedDigit()
            .padding(.horizontal, 7)
            .padding(.vertical, 2)
            .foregroundStyle(severity == .medium ? Color.black.opacity(0.8) : .white)
            .background(severity.color, in: Capsule())
    }
}

struct GradeBadge: View {
    let grade: String
    var size: CGFloat = 36

    var body: some View {
        Text(grade)
            .font(.system(size: size * 0.55, weight: .bold, design: .rounded))
            .foregroundStyle(.white)
            .frame(width: size, height: size)
            .background(color, in: RoundedRectangle(cornerRadius: size * 0.25))
    }

    private var color: Color {
        switch grade {
        case "–": .gray
        case "A": .green
        case "B": .mint
        case "C": .yellow
        case "D": .orange
        default: .red
        }
    }
}

struct NewBadge: View {
    var body: some View {
        Text("NUOVO")
            .font(.system(size: 9, weight: .heavy))
            .padding(.horizontal, 4)
            .padding(.vertical, 1)
            .foregroundStyle(.orange)
            .overlay(Capsule().stroke(.orange, lineWidth: 1))
            .help("Dispositivo non ancora segnato come noto")
    }
}
