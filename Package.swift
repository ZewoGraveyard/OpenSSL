import PackageDescription

let package = Package(
	name: "OpenSSL",
	dependencies: [
		.Package(url: "https://github.com/Zewo/COpenSSL.git", majorVersion: 0, minor: 1),
		.Package(url: "https://github.com/Zewo/SSL.git", majorVersion: 0, minor: 1),
		.Package(url: "https://github.com/Zewo/Stream.git", majorVersion: 0, minor: 1)
	]
)
