import PackageDescription

let package = Package(
    name: "OpenSSL",
    dependencies: [
        .Package(url: "https://github.com/open-swift/C7.git", majorVersion: 0, minor: 9),
        .Package(url: "https://github.com/Zewo/COpenSSL.git", majorVersion: 0, minor: 6)
    ]
)
