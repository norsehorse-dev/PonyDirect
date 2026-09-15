// swift-tools-version: 5.9
import PackageDescription

let package = Package(
    name: "PonyDirect",
    platforms: [.iOS(.v14), .macOS(.v11)],
    products: [
        .library(name: "PonyDirect", targets: ["PonyDirect"]),
    ],
    targets: [
        .target(name: "PonyDirect"),
        .testTarget(name: "PonyDirectTests", dependencies: ["PonyDirect"]),
    ]
)
