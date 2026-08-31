// swift-tools-version:5.9
// PCUnlockApp — iOS Swift Package
// Platforms: iOS 16+ (Secure Enclave P-256 via CryptoKit)

import PackageDescription

let package = Package(
    name: "PCUnlockApp",
    platforms: [
        .iOS(.v16)
    ],
    products: [
        .library(
            name: "PCUnlockApp",
            targets: ["PCUnlockApp"]
        )
    ],
    dependencies: [
        // SwiftCheck — property-based testing framework for Swift
        // https://github.com/typelift/SwiftCheck
        .package(
            url: "https://github.com/typelift/SwiftCheck.git",
            from: "0.12.0"
        )
    ],
    targets: [
        .target(
            name: "PCUnlockApp",
            path: "Sources"
        ),
        .testTarget(
            name: "PCUnlockAppTests",
            dependencies: [
                "PCUnlockApp",
                .product(name: "SwiftCheck", package: "SwiftCheck")
            ],
            path: "Tests"
        )
    ]
)
