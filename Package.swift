// swift-tools-version: 6.0
import PackageDescription

let package = Package(
    name: "SubnetScout",
    defaultLocalization: "it",
    platforms: [.macOS(.v14)],
    products: [
        .executable(name: "SubnetScout", targets: ["SubnetScout"]),
        .executable(name: "SubnetScoutHelper", targets: ["SubnetScoutHelper"]),
        .library(name: "ScanKit", targets: ["ScanKit"]),
    ],
    targets: [
        // Motore: esecuzione di nmap, parsing XML, audit, diff, report. Nessuna dipendenza UI.
        .target(name: "ScanKit"),
        // App SwiftUI.
        .executableTarget(
            name: "SubnetScout",
            dependencies: ["ScanKit"],
            linkerSettings: [
                // Incorpora Info.plist nel binario, così anche `swift run` ha
                // NSLocalNetworkUsageDescription (permesso "Rete locale").
                .unsafeFlags([
                    "-Xlinker", "-sectcreate",
                    "-Xlinker", "__TEXT",
                    "-Xlinker", "__info_plist",
                    "-Xlinker", "Resources/Info.plist",
                ]),
            ]
        ),
        // Daemon root (SMAppService) che esegue nmap per conto dell'app via XPC.
        .executableTarget(name: "SubnetScoutHelper", dependencies: ["ScanKit"]),
        .testTarget(name: "ScanKitTests", dependencies: ["ScanKit"]),
    ]
)
