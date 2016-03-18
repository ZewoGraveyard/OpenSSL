import PackageDescription

let package = Package(
    name: "OpenSSL",
    dependencies: [
        .Package(url: "https://github.com/Zewo/Stream.git", majorVersion: 0, minor: 4),
        .Package(url: "https://github.com/Zewo/File.git", majorVersion: 0, minor: 4),
        .Package(url: "https://github.com/Zewo/Venice.git", majorVersion: 0, minor: 4),
    ]
)

#if os(OSX)
package.dependencies.append(.Package(url: "https://github.com/Zewo/COpenSSL-OSX.git", majorVersion: 0, minor: 4))
#else
package.dependencies.append(.Package(url: "https://github.com/Zewo/COpenSSL.git", majorVersion: 0, minor: 4))
#endif
