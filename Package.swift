import PackageDescription

#if os(OSX)
    let openSSLURL = "https://github.com/Zewo/COpenSSL-OSX.git"
#else
    let openSSLURL = "https://github.com/Zewo/COpenSSL.git"
#endif

let package = Package(
	name: "OpenSSL",
	dependencies: [
		.Package(url: openSSLURL, majorVersion: 0, minor: 1),
		.Package(url: "https://github.com/Zewo/Core.git", majorVersion: 0, minor: 1),
		.Package(url: "https://github.com/Zewo/CURIParser.git", majorVersion: 0, minor: 1)
	]
)
