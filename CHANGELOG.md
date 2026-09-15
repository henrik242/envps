# Changelog

All notable changes to envps are documented here. Versions correspond to git tags.

## 2.0.1 - 2026-07-09
[diff](https://github.com/henrik242/envps/compare/2.0.0...2.0.1)
- Fix artifact uploads: rename to unique paths before upload.

## 2.0.0 - 2026-07-09
[diff](https://github.com/henrik242/envps/compare/1.6...2.0.0)
- Rewrite in Rust.
- Fix Linux, FreeBSD, and NetBSD builds.
- Skip zipping build artifacts (upload-artifact `archive: false`).
- Update `actions/checkout` to v6.

## 1.6 - 2026-07-09
[diff](https://github.com/henrik242/envps/compare/1.5...1.6)
- Add `-v` flag to show version.
- Release workflow: support multi-digit versions, prefix release name with `envps`.

## 1.5 - 2026-07-09
[diff](https://github.com/henrik242/envps/compare/1.4...1.5)
- Add release workflow to create GitHub releases on version tags.
- Add FreeBSD/NetBSD CI (using gmake for GNU make compatibility).
- Fix FreeBSD build (missing `fcntl.h`).
- Clean up dead code inherited from xproc, fix error handling.
- Build artifacts for all targets.

## 1.4 - 2024-01-12
[diff](https://github.com/henrik242/envps/compare/1.3...1.4)
- Rename project to envps.
- Add install guide.
- Disable debug build.

## 1.3 - 2024-01-11
[diff](https://github.com/henrik242/envps/compare/1.2...1.3)
- Handle invalid input PID.

## 1.2 - 2024-01-11
[diff](https://github.com/henrik242/envps/compare/1.1...1.2)
- Strip unused code and add helpful logging.
- Build Linux binary too.
- Add upstream credits.

## 1.1 - 2024-01-10
[diff](https://github.com/henrik242/envps/compare/1.0...1.1)
- Add `<algorithm>` include needed by `std::sort` on Linux/g++.

## 1.0 - 2024-01-10
[release](https://github.com/henrik242/envps/releases/tag/1.0)
- Initial release. Add `<unordered_map>` include.
