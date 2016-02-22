import PackageDescription

#if os(OSX)
    let openSSLURL = "https://github.com/Zewo/COpenSSL-OSX.git"
#else
    let openSSLURL = "https://github.com/Zewo/COpenSSL.git"
#endif

let package = Package(
    name: "OpenSSL",
    dependencies: [
        .Package(url: openSSLURL, majorVersion: 0, minor: 2),
        .Package(url: "https://github.com/Zewo/Stream.git", majorVersion: 0, minor: 2),
        .Package(url: "https://github.com/Zewo/File.git", majorVersion: 0, minor: 2),
        .Package(url: "https://github.com/Zewo/Venice.git", majorVersion: 0, minor: 2),
        .Package(url: "https://github.com/Zewo/CLibvenice.git", majorVersion: 0, minor: 2)
    ]
)
