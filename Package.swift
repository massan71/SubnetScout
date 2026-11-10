// swift-tools-version: 6.0
import PackageDescription

let package = Package(
    name: "SubnetScout",
    defaultLocalization: "en",
    platforms: [.macOS(.v14)],
    products: [
        .executable(name: "SubnetScout", targets: ["SubnetScout"]),
        .executable(name: "SubnetScoutHelper", targets: ["SubnetScoutHelper"]),
        .library(name: "ScanKit", targets: ["ScanKit"]),
    ],
    targets: [
        // Engine: runs nmap, parses XML, audit, diff, report. No UI dependencies.
        .target(name: "ScanKit"),
        // SwiftUI app.
        .executableTarget(
            name: "SubnetScout",
            dependencies: ["ScanKit"],
            linkerSettings: [
                // Embeds Info.plist in the binary, so that even `swift run` has
                // NSLocalNetworkUsageDescription (Local Network permission).
                .unsafeFlags([
                    "-Xlinker", "-sectcreate",
                    "-Xlinker", "__TEXT",
                    "-Xlinker", "__info_plist",
                    "-Xlinker", "Resources/Info.plist",
                ]),
            ]
        ),
        // Root daemon (SMAppService) that runs nmap on behalf of the app over XPC.
        .executableTarget(name: "SubnetScoutHelper", dependencies: ["ScanKit"]),
        .testTarget(name: "ScanKitTests", dependencies: ["ScanKit"]),
    ]
)
