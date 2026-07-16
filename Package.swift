// swift-tools-version: 6.0

import PackageDescription

let package = Package(
    name: "UniVPNClashBridge",
    platforms: [.macOS(.v15)],
    products: [
        .executable(name: "UniVPNClashBridge", targets: ["UniVPNClashBridge"]),
    ],
    targets: [
        .target(name: "BridgeCore"),
        .executableTarget(
            name: "UniVPNClashBridge",
            dependencies: ["BridgeCore"]
        ),
        .executableTarget(
            name: "BridgeCoreSelfTest",
            dependencies: ["BridgeCore"]
        ),
        .executableTarget(name: "IconPackager"),
        .executableTarget(name: "UniVPNDNSGuard"),
    ]
)
