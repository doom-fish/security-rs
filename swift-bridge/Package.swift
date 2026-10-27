// swift-tools-version: 5.9
import PackageDescription

let package = Package(
    name: "SecurityBridge",
    platforms: [
        .macOS(.v12)
    ],
    products: [
        .library(
            name: "SecurityBridge",
            type: .static,
            targets: ["SecurityBridge"]
        )
    ],
    targets: [
        .target(
            name: "SecurityBridgeABI",
            path: "Sources/SecurityBridgeABI",
            publicHeadersPath: "include"
        ),
        .target(
            name: "SecurityBridge",
            dependencies: ["SecurityBridgeABI"],
            path: "Sources/SecurityBridge"
        )
    ]
)
