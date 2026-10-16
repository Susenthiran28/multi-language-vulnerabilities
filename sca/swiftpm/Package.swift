// swift-tools-version:5.7
// File:    Package.swift
// Purpose: SCA fixture. SwiftPM manifest pinned to known-vulnerable releases.
//          DO NOT BUILD.
// Author:  Vigilnz Security Engineering
// Date:    2026-10-16

import PackageDescription

let package = Package(
    name: "VulnCorpusSwiftPM",
    products: [
        .library(name: "VulnCorpusSwiftPM", targets: ["VulnCorpusSwiftPM"])
    ],
    dependencies: [
        .package(url: "https://github.com/vapor/vapor.git", exact: "4.0.0"),
        .package(url: "https://github.com/apple/swift-nio.git", exact: "2.29.0"),
        .package(url: "https://github.com/apple/swift-crypto.git", exact: "1.1.0"),
        .package(url: "https://github.com/Alamofire/Alamofire.git", exact: "5.2.0")
    ],
    targets: [
        .target(name: "VulnCorpusSwiftPM", dependencies: [])
    ]
)
