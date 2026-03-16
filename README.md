envps
-----
Show process environment variables
```
$ envps 242
SERVICE_NAME=example
PATH=/usr/bin:/bin:/usr/sbin:/sbin
```

Installation
------------
Just run `make` (requires [Rust](https://www.rust-lang.org/tools/install)) or install with [Homebrew](https://brew.sh/) (both Linux and macOS are supported):
```
$ brew install henrik242/brew/envps
```

Supported platforms: Linux, macOS, FreeBSD, NetBSD.

Links
-----
* The original C++ version was based on functionality from [an old version](https://github.com/henrik242/xproc/tree/fd06a3e5978c99a33ef57bc13b577eab8648cdcd) of https://github.com/samuelvenable/xproc. Thanks!
* The Homebrew formula is hosted at https://github.com/henrik242/homebrew-brew/blob/main/Formula/envps.rb
