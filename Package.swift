import PackageDescription

#if os(OSX)
    let COpenSSLURL = "https://github.com/Zewo/COpenSSL-OSX.git"
#else
    let COpenSSLURL = "https://github.com/Zewo/COpenSSL.git"
#endif

let package = Package(
    name: "OpenSSL",
    dependencies: [
        .Package(url: "https://github.com/VeniceX/File.git", majorVersion: 0, minor: 5),
        .Package(url: COpenSSLURL, majorVersion: 0, minor: 2),
    ]
)
