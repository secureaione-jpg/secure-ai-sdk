// swift-tools-version:5.9
import PackageDescription

// At the repository root because Swift Package Manager only looks here; the
// code is in swift/. No dependencies, for the same reason as the other
// clients: a privacy library that is awkward to add is one that gets left out.
let package = Package(
    name: "SecureAI",
    platforms: [.iOS(.v15), .macOS(.v12), .watchOS(.v8), .tvOS(.v15), .visionOS(.v1)],
    products: [
        .library(name: "SecureAI", targets: ["SecureAI"]),
    ],
    targets: [
        .target(name: "SecureAI", path: "swift/Sources/SecureAI"),
        .testTarget(name: "SecureAITests", dependencies: ["SecureAI"], path: "swift/Tests/SecureAITests"),
    ]
)
