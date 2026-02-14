# envps

C++17 tool that shows process environment variables. Built with `make`.

## Releasing

1. Bump `VERSION` in `envps.cpp`
2. Commit, tag, and push. Tags have **no `v` prefix** (e.g., `1.6`, not `v1.6`)
3. The GitHub Actions release workflow (`.github/workflows/release.yml`) triggers on the tag push
4. Update the Homebrew formula in `../homebrew-brew/Formula/envps.rb`:
   - Update the `url` tag version
   - Recompute `sha256`: `curl -sL https://github.com/henrik242/envps/archive/refs/tags/<version>.tar.gz | shasum -a 256`
   - If the tag is recreated (moved), the sha256 changes and must be recomputed

## Commit style

Lowercase, concise messages (e.g., `envps 1.6`, `fix FreeBSD build`).
