import PackageDescription

let package = Package(
    name: "OpenSSL",
    dependencies: [
        .Package(url: "https://github.com/VeniceX/File.git", majorVersion: 0, minor: 8),
        .Package(url: "https://github.com/Zewo/COpenSSL.git", majorVersion: 0, minor: 6),
    ]
)
