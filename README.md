OpenSSL
=======

[![Swift 3.0](https://img.shields.io/badge/Swift-3.0-orange.svg?style=flat)](https://swift.org)
[![Platforms Linux](https://img.shields.io/badge/Platforms-Linux-lightgray.svg?style=flat)](https://swift.org/download/#linux)
[![License MIT](https://img.shields.io/badge/License-MIT-blue.svg?style=flat)](https://tldrlegal.com/license/mit-license)
[![Slack Status](http://slack.zewo.io/badge.svg)](http://slack.zewo.io)

**OpenSSL** for **Swift 3.0**.

## Installation

### OSX

- Install openssl using homebrew

```bash
$ brew install openssl
$ brew link openssl --force # the OpenSSL headers & dylib are not by default symlinked to /usr/local/lib by homebrew
```

- Build

```bach
$ swift build -Xcc -I/usr/local/include -Xlinker -L/usr/local/lib/
```

### Linux

- Install `libssl-dev`

```bash
$ apt-get install libssl-dev
```

- Add `OpenSSL` to your `Package.swift`

```swift
import PackageDescription

let package = Package(
	dependencies: [
		.Package(url: "https://github.com/Zewo/OpenSSL.git", majorVersion: 0, minor: 4)
	]
)

```

## Community

[![Slack](http://s13.postimg.org/ybwy92ktf/Slack.png)](http://slack.zewo.io)

Join us on [Slack](http://slack.zewo.io).

License
-------

**OpenSSL** is released under the MIT license. See LICENSE for details.
