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
            name: "SecurityBridge",
            path: "Sources/SecurityBridge"
        )
    ]
)
