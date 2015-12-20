import PackageDescription

let package = Package(
	name: "OpenSSL",
	dependencies: [
		.Package(url: "https://github.com/Zewo/COpenSSL.git", majorVersion: 0, minor: 1),
		.Package(url: "https://github.com/Zewo/Core.git", majorVersion: 0, minor: 1),
		.Package(url: "https://github.com/Zewo/CURIParser.git", majorVersion: 0, minor: 1)
	]
)
